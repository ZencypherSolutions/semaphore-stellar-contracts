pub fn example() -> &'static str {
    "Hello, Semaphore_key_pts!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_semaphore() {
        let result = example();
        assert_eq!(result, "Hello, Semaphore_key_pts!");
    }
}
