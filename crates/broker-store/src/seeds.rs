//! Initial rows are data, not an authenticated role or an authorization decision.
use crate::time::TimestampMicros;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAction {
    SessionRead,
    ConfigurationRead,
    GrantsRead,
    GrantsWrite,
    RolesRead,
    RolesWrite,
    UsersRead,
    UsersWrite,
    ProjectsRead,
}

impl SystemAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionRead => "session.read",
            Self::ConfigurationRead => "configuration.read",
            Self::GrantsRead => "grants.read",
            Self::GrantsWrite => "grants.write",
            Self::RolesRead => "roles.read",
            Self::RolesWrite => "roles.write",
            Self::UsersRead => "users.read",
            Self::UsersWrite => "users.write",
            Self::ProjectsRead => "projects.read",
        }
    }
}

pub const ADMIN_ACTIONS: &[SystemAction] = &[
    SystemAction::SessionRead,
    SystemAction::ConfigurationRead,
    SystemAction::GrantsRead,
    SystemAction::GrantsWrite,
    SystemAction::RolesRead,
    SystemAction::RolesWrite,
    SystemAction::UsersRead,
    SystemAction::UsersWrite,
    SystemAction::ProjectsRead,
];
pub const USER_ACTIONS: &[SystemAction] = &[SystemAction::SessionRead, SystemAction::ProjectsRead];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinRole {
    Admin,
    User,
}

impl BuiltinRole {
    pub const ALL: &[Self] = &[Self::Admin, Self::User];
    pub const fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
    pub const fn actions(self) -> &'static [SystemAction] {
        match self {
            Self::Admin => ADMIN_ACTIONS,
            Self::User => USER_ACTIONS,
        }
    }
}

/// Fixed initial ACL fence; subsequent writes must use transactional compare-and-swap.
pub const INITIAL_ACL_REVISION: i64 = 1;

/// The eventual SQL adapter supplies one captured timestamp to all initial rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialSeeds {
    timestamp: TimestampMicros,
}

impl InitialSeeds {
    pub const fn new(timestamp: TimestampMicros) -> Self {
        Self { timestamp }
    }
    pub const fn timestamp(self) -> TimestampMicros {
        self.timestamp
    }
    pub const fn roles(self) -> &'static [BuiltinRole] {
        BuiltinRole::ALL
    }
    pub fn permissions(self) -> impl Iterator<Item = (BuiltinRole, SystemAction)> {
        BuiltinRole::ALL.iter().copied().flat_map(|role| {
            role.actions()
                .iter()
                .copied()
                .map(move |action| (role, action))
        })
    }
    pub const fn acl_revision(self) -> i64 {
        INITIAL_ACL_REVISION
    }
}
