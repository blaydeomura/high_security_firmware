use ring::error::KeyRejected;
use std::{error::Error, fmt};

//Error handling
#[derive(Debug)]
pub enum MyError {
    KeyRejected(KeyRejected),
    Unspecified(ring::error::Unspecified), // Add this line
                                           // expand on cases later
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::KeyRejected(e) => write!(f, "Key rejected: {:?}", e),
            MyError::Unspecified(_) => write!(f, "An unspecified error occurred"),
            // Input other cases here
        }
    }
}

impl Error for MyError {}

impl From<KeyRejected> for MyError {
    fn from(err: KeyRejected) -> MyError {
        MyError::KeyRejected(err)
    }
}

impl From<ring::error::Unspecified> for MyError {
    fn from(err: ring::error::Unspecified) -> MyError {
        MyError::Unspecified(err)
    }
}
