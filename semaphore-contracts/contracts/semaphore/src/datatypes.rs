use soroban_sdk::{contracttype, Address, String};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    GroupDoesNotExist = 1,
    CallerIsNotTheGroupAdmin = 2,
    CallerIsNotThePendingGroupAdmin = 3,
}