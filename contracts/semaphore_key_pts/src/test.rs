#[cfg(test)]
mod test {
    use super::*;

    fn create_test_env() -> (Env, SemaphoreVerifierKeyPtsClient) {
        let env = Env::default();
        let contract_id = env.register(None, SemaphoreVerifierKeyPts);
        let client = SemaphoreVerifierKeyPtsClient::new(&env, &contract_id);
        (env, client)
    }

    #[test]
    fn test_initialize() {
        let (_, client) = create_test_env();
        client.initialize();
        let points = client.get_pts(&1);
        assert!(!points.is_empty(), "Points should be initialized");
    }

    #[test]
    fn test_get_pts() {
        let (_, client) = create_test_env();
        client.initialize();
        let points = client.get_pts(&1);
        assert!(!points.is_empty(), "Should return non-empty points array");
        assert_eq!(points.len(), 8, "Should return exactly 8 points");
    }

    #[test]
    fn test_check_invariant() {
        let (_, client) = create_test_env();
        client.initialize();
        assert_eq!(client.try_check_invariant(&1), Ok(Ok(())));
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #1)")]
    fn test_check_invariant_panic() {
        let (_, client) = create_test_env();
        client.initialize();
        client.check_invariant(&2);
    }
}