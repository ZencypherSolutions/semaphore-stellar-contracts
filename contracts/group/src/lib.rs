pub fn example() -> &'static str {
    "Hello, Group!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_group() {
        let result = example();
        assert_eq!(result, "Hello, Group!");
    }
}