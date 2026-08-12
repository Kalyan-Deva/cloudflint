//! What an expression looks like after parsing, before it gets lowered to closures.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Method,
    Uri,
    Path,
    Query,
    Body,
    Host,
    Header(String),
    IpSrc,
    /// Whether the client reached us over https. A boolean, so it takes no operator.
    Ssl,
}

impl Field {
    pub fn is_body(&self) -> bool {
        matches!(self, Field::Body)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Contains,
    Matches,
    In,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Str(String),
    List(Vec<String>),
    /// `$name`, resolved against the config's named lists at compile time.
    Named(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Cmp {
        field: Field,
        op: Op,
        operand: Operand,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

impl Expr {
    /// Whether this rule can be judged from the head alone. Rules that say no get
    /// held back until the body has been buffered, so a request blocked on its
    /// headers never costs us a body read.
    pub fn needs_body(&self) -> bool {
        match self {
            Expr::Cmp { field, .. } => field.is_body(),
            Expr::And(a, b) | Expr::Or(a, b) => a.needs_body() || b.needs_body(),
            Expr::Not(a) => a.needs_body(),
        }
    }
}
