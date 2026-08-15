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
    /// ISO 3166-1 alpha-2, from the country database.
    GeoCountry,
    /// Two-letter continent code.
    GeoContinent,
    /// The AS organisation name, for rules about a provider rather than a number.
    GeoAsOrg,
    /// Bare booleans, like `ssl`: a datacenter network, a VPN or proxy, a Tor exit, and
    /// "deliberately hiding" which is the last two together.
    IpHosting,
    IpVpn,
    IpTor,
    IpAnonymous,
    /// How automated the request looks, 1..=99.
    BotScore,
    /// A crawler that proved itself. A bare boolean, like `ssl`.
    BotVerified,
    /// The recognised crawler's name.
    BotName,
    /// Autonomous system number. Compared as its decimal text, so `eq "64512"` and
    /// `in {"64512" "64513"}` work with the same machinery every other field uses.
    GeoAsn,
}

impl Field {
    pub fn is_body(&self) -> bool {
        matches!(self, Field::Body)
    }

    /// Whether evaluating this needs a geo database loaded.
    pub fn is_geoip(&self) -> bool {
        matches!(
            self,
            Field::GeoCountry
                | Field::GeoAsn
                | Field::GeoContinent
                | Field::GeoAsOrg
                | Field::IpHosting
                | Field::IpVpn
                | Field::IpTor
                | Field::IpAnonymous
        )
    }

    /// Fields that stand alone with no operator, the way `ssl` does.
    pub fn is_bare_bool(&self) -> bool {
        matches!(
            self,
            Field::Ssl
                | Field::IpHosting
                | Field::IpVpn
                | Field::IpTor
                | Field::IpAnonymous
                | Field::BotVerified
        )
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

    /// Whether anything in here needs a geo database to mean anything.
    pub fn needs_geoip(&self) -> bool {
        match self {
            Expr::Cmp { field, .. } => field.is_geoip(),
            Expr::And(a, b) | Expr::Or(a, b) => a.needs_geoip() || b.needs_geoip(),
            Expr::Not(a) => a.needs_geoip(),
        }
    }
}
