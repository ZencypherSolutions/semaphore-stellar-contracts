pub fn example() -> &'static str {
    "Hello, Verifier!"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_verifier() {
        let result = example();
        assert_eq!(result, "Hello, Verifier!");
    }
}
