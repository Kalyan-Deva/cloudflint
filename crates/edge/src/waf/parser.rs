//! Lexer and recursive descent parser for the rule expression language.
//!
//! ```text
//! expr    := or
//! or      := and ("or" and)*
//! and     := unary ("and" unary)*
//! unary   := "not" unary | atom
//! atom    := "(" expr ")" | cmp
//! cmp     := field ["[" string "]"] op operand
//! op      := eq | ne | contains | matches | in
//! operand := string | "[" string ("," string)* "]" | "$" name
//! ```
//!
//! Runs once at config load. Nothing here is on the request path.

use anyhow::{anyhow, bail, Result};

use super::ast::{Expr, Field, Op, Operand};

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Named(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

struct Token {
    tok: Tok,
    at: usize,
}

pub fn parse(src: &str) -> Result<Expr> {
    let toks = lex(src)?;
    if toks.is_empty() {
        bail!("empty expression");
    }
    let mut p = Parser { toks, i: 0 };
    let expr = p.or_expr()?;
    if p.i < p.toks.len() {
        bail!("unexpected trailing input at column {}", p.col());
    }
    Ok(expr)
}

fn lex(src: &str) -> Result<Vec<Token>> {
    let cs: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;

    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        let at = i;

        match c {
            '(' | ')' | '[' | ']' | ',' => {
                let tok = match c {
                    '(' => Tok::LParen,
                    ')' => Tok::RParen,
                    '[' => Tok::LBracket,
                    ']' => Tok::RBracket,
                    _ => Tok::Comma,
                };
                out.push(Token { tok, at });
                i += 1;
            }
            '"' => {
                i += 1;
                let mut s = String::new();
                loop {
                    let Some(&ch) = cs.get(i) else {
                        bail!("unterminated string starting at column {}", at + 1);
                    };
                    match ch {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '\\' => match cs.get(i + 1) {
                            Some('"') => {
                                s.push('"');
                                i += 2;
                            }
                            Some('\\') => {
                                s.push('\\');
                                i += 2;
                            }
                            /* every other escape is left exactly as written, so regex
                               classes like \s and \b survive into the pattern */
                            Some(_) => {
                                s.push('\\');
                                i += 1;
                            }
                            None => bail!("unterminated string starting at column {}", at + 1),
                        },
                        _ => {
                            s.push(ch);
                            i += 1;
                        }
                    }
                }
                out.push(Token { tok: Tok::Str(s), at });
            }
            '$' => {
                i += 1;
                let start = i;
                while i < cs.len() && is_name(cs[i]) {
                    i += 1;
                }
                if i == start {
                    bail!("expected a list name after `$` at column {}", at + 1);
                }
                let name = cs[start..i].iter().collect();
                out.push(Token { tok: Tok::Named(name), at });
            }
            c if is_name(c) || c == '.' => {
                let start = i;
                while i < cs.len() && (is_name(cs[i]) || cs[i] == '.') {
                    i += 1;
                }
                let name = cs[start..i].iter().collect();
                out.push(Token { tok: Tok::Ident(name), at });
            }
            _ => bail!("unexpected character `{c}` at column {}", at + 1),
        }
    }
    Ok(out)
}

fn is_name(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '-'
}

struct Parser {
    toks: Vec<Token>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i).map(|t| &t.tok)
    }

    /// 1-based column of the token we're looking at, for error messages.
    fn col(&self) -> usize {
        match self.toks.get(self.i) {
            Some(t) => t.at + 1,
            None => self.toks.last().map_or(1, |t| t.at + 2),
        }
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if let Some(Tok::Ident(s)) = self.peek() {
            if s.eq_ignore_ascii_case(kw) {
                self.i += 1;
                return true;
            }
        }
        false
    }

    fn eat(&mut self, want: &Tok) -> bool {
        if self.peek() == Some(want) {
            self.i += 1;
            return true;
        }
        false
    }

    fn or_expr(&mut self) -> Result<Expr> {
        let mut left = self.and_expr()?;
        while self.eat_kw("or") {
            let right = self.and_expr()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and_expr(&mut self) -> Result<Expr> {
        let mut left = self.unary()?;
        while self.eat_kw("and") {
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr> {
        if self.eat_kw("not") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Expr> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.i += 1;
                let inner = self.or_expr()?;
                if !self.eat(&Tok::RParen) {
                    bail!("expected `)` at column {}", self.col());
                }
                Ok(inner)
            }
            Some(Tok::Ident(_)) => self.cmp(),
            Some(_) => bail!("expected a field at column {}", self.col()),
            None => bail!("expression ends early, expected a field"),
        }
    }

    fn cmp(&mut self) -> Result<Expr> {
        let Some(Token { tok: Tok::Ident(name), at }) = self.toks.get(self.i) else {
            bail!("expected a field at column {}", self.col());
        };
        let (name, at) = (name.clone(), *at);
        self.i += 1;

        /* these are already a yes or no, so they stand alone: `ssl`, or `not ip.src.is_tor` */
        let bare = match name.as_str() {
            "ssl" => Some(Field::Ssl),
            "ip.src.is_hosting" => Some(Field::IpHosting),
            "ip.src.is_vpn" => Some(Field::IpVpn),
            "ip.src.is_tor" => Some(Field::IpTor),
            "ip.src.is_anonymous" => Some(Field::IpAnonymous),
            _ => None,
        };
        if let Some(field) = bare {
            return Ok(Expr::Cmp {
                field,
                op: Op::Eq,
                operand: Operand::Str("true".into()),
            });
        }

        /* http.request.headers["user-agent"] */
        let mut key = None;
        if self.eat(&Tok::LBracket) {
            let Some(Tok::Str(k)) = self.peek().cloned() else {
                bail!("expected a quoted header name at column {}", self.col());
            };
            self.i += 1;
            if !self.eat(&Tok::RBracket) {
                bail!("expected `]` at column {}", self.col());
            }
            key = Some(k);
        }
        let field = field_from(&name, key.as_deref(), at)?;

        let Some(Tok::Ident(opname)) = self.peek().cloned() else {
            bail!("expected an operator after `{name}` at column {}", self.col());
        };
        let op = match opname.to_ascii_lowercase().as_str() {
            "eq" => Op::Eq,
            "ne" => Op::Ne,
            "contains" => Op::Contains,
            "matches" => Op::Matches,
            "in" => Op::In,
            other => bail!(
                "unknown operator `{other}` at column {} (have: eq, ne, contains, matches, in)",
                self.col()
            ),
        };
        self.i += 1;

        let operand = self.operand(&opname)?;
        Ok(Expr::Cmp { field, op, operand })
    }

    fn operand(&mut self, after: &str) -> Result<Operand> {
        match self.peek().cloned() {
            Some(Tok::Str(s)) => {
                self.i += 1;
                Ok(Operand::Str(s))
            }
            Some(Tok::Named(n)) => {
                self.i += 1;
                Ok(Operand::Named(n))
            }
            Some(Tok::LBracket) => {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    let Some(Tok::Str(s)) = self.peek().cloned() else {
                        bail!("expected a quoted value at column {}", self.col());
                    };
                    self.i += 1;
                    items.push(s);
                    if !self.eat(&Tok::Comma) {
                        break;
                    }
                }
                if !self.eat(&Tok::RBracket) {
                    bail!("expected `]` at column {}", self.col());
                }
                Ok(Operand::List(items))
            }
            _ => bail!("expected a value after `{after}` at column {}", self.col()),
        }
    }
}

fn field_from(name: &str, key: Option<&str>, at: usize) -> Result<Field> {
    let col = at + 1;
    let field = match (name, key) {
        ("http.request.method", None) => Field::Method,
        ("http.request.uri", None) => Field::Uri,
        ("http.request.uri.path", None) => Field::Path,
        ("http.request.uri.query", None) => Field::Query,
        ("http.request.body", None) => Field::Body,
        ("http.host", None) => Field::Host,
        ("http.request.headers", Some(k)) => Field::Header(k.to_ascii_lowercase()),
        ("http.request.headers", None) => bail!(
            "http.request.headers needs a name, like http.request.headers[\"user-agent\"] (column {col})"
        ),
        ("ip.src", None) => Field::IpSrc,
        ("ssl", None) => Field::Ssl,
        ("ip.geoip.country", None) => Field::GeoCountry,
        ("ip.geoip.asnum", None) => Field::GeoAsn,
        ("ip.geoip.continent", None) => Field::GeoContinent,
        ("ip.geoip.asorg", None) => Field::GeoAsOrg,
        (_, Some(_)) => bail!("`{name}` does not take a [\"...\"] key (column {col})"),
        _ => {
            return Err(anyhow!(
                "unknown field `{name}` at column {col}\n\
                 have: http.request.method, http.request.uri, http.request.uri.path,\n\
                 \x20     http.request.uri.query, http.request.body, http.host,\n\
                 \x20     http.request.headers[\"...\"], ip.src, ssl,\n\
                 \x20     ip.geoip.country, ip.geoip.continent, ip.geoip.asnum,\n\
                 \x20     ip.geoip.asorg, ip.src.is_hosting, ip.src.is_vpn,\n\
                 \x20     ip.src.is_tor, ip.src.is_anonymous"
            ))
        }
    };
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(field: Field, op: Op, operand: Operand) -> Expr {
        Expr::Cmp { field, op, operand }
    }

    #[test]
    fn parses_a_simple_comparison() {
        assert_eq!(
            parse(r#"http.request.uri.path contains "/admin""#).unwrap(),
            cmp(Field::Path, Op::Contains, Operand::Str("/admin".into()))
        );
    }

    #[test]
    fn and_binds_tighter_than_or() {
        let e = parse(
            r#"http.host eq "a" or http.host eq "b" and http.request.method eq "GET""#,
        )
        .unwrap();
        let Expr::Or(left, right) = e else {
            panic!("expected the top level to be an or, got {e:?}");
        };
        assert_eq!(*left, cmp(Field::Host, Op::Eq, Operand::Str("a".into())));
        assert!(matches!(*right, Expr::And(_, _)));
    }

    #[test]
    fn parens_override_precedence() {
        let e = parse(
            r#"(http.host eq "a" or http.host eq "b") and http.request.method eq "GET""#,
        )
        .unwrap();
        assert!(matches!(e, Expr::And(_, _)));
    }

    #[test]
    fn not_applies_to_the_next_atom_only() {
        let e = parse(r#"not http.host eq "a" and http.host eq "b""#).unwrap();
        let Expr::And(left, _) = e else {
            panic!("expected an and at the top, got {e:?}");
        };
        assert!(matches!(*left, Expr::Not(_)));
    }

    #[test]
    fn reads_header_lookups_and_lists() {
        assert_eq!(
            parse(r#"http.request.headers["User-Agent"] in ["curl", "wget"]"#).unwrap(),
            cmp(
                Field::Header("user-agent".into()),
                Op::In,
                Operand::List(vec!["curl".into(), "wget".into()])
            )
        );
        assert_eq!(
            parse("ip.src in $trusted").unwrap(),
            cmp(Field::IpSrc, Op::In, Operand::Named("trusted".into()))
        );
    }

    #[test]
    fn keeps_regex_escapes_intact() {
        let e = parse(r#"http.request.uri.query matches "(?i)\bunion\s+select\b""#).unwrap();
        let Expr::Cmp { operand: Operand::Str(pat), .. } = e else {
            panic!("expected a comparison");
        };
        assert_eq!(pat, r"(?i)\bunion\s+select\b");
    }

    #[test]
    fn unescapes_quotes_and_backslashes() {
        let e = parse(r#"http.request.uri.query contains "say \"hi\" \\ ok""#).unwrap();
        let Expr::Cmp { operand: Operand::Str(s), .. } = e else {
            panic!("expected a comparison");
        };
        assert_eq!(s, r#"say "hi" \ ok"#);
    }

    #[test]
    fn body_is_the_only_field_that_needs_buffering() {
        assert!(!parse(r#"http.request.uri.path contains "/a""#).unwrap().needs_body());
        assert!(parse(r#"http.request.body contains "a""#).unwrap().needs_body());
        assert!(parse(r#"http.host eq "a" or http.request.body contains "b""#)
            .unwrap()
            .needs_body());
    }

    #[test]
    fn rejects_nonsense_with_a_column() {
        let cases = [
            ("", "empty"),
            ("http.request.uri.path", "no operator"),
            (r#"http.request.uri.path contains"#, "no value"),
            (r#"http.request.uri.path wat "x""#, "bad operator"),
            (r#"nonsense.field eq "x""#, "unknown field"),
            (r#"(http.host eq "a""#, "unclosed paren"),
            (r#"http.request.uri.path contains "unterminated"#, "unterminated string"),
            (r#"http.request.headers eq "x""#, "header with no name"),
            (r#"http.host eq "a" extra"#, "trailing input"),
        ];
        for (src, why) in cases {
            assert!(parse(src).is_err(), "should have rejected {why}: {src}");
        }
    }

    #[test]
    fn the_geoip_fields_parse_now_that_there_is_a_reader_for_them() {
        assert_eq!(
            parse(r#"ip.geoip.country eq "US""#).unwrap(),
            Expr::Cmp {
                field: Field::GeoCountry,
                op: Op::Eq,
                operand: Operand::Str("US".into()),
            }
        );
        assert_eq!(
            parse(r#"ip.geoip.asnum eq "64512""#).unwrap(),
            Expr::Cmp {
                field: Field::GeoAsn,
                op: Op::Eq,
                operand: Operand::Str("64512".into()),
            }
        );
    }

    #[test]
    fn an_unknown_field_lists_the_ones_that_exist() {
        let e = match parse(r#"ip.geoip.city eq "London""#) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("there is no city field"),
        };
        assert!(e.contains("unknown field"), "unhelpful error: {e}");
        assert!(e.contains("ip.geoip.country"), "the list should mention what does exist: {e}");
    }
}
