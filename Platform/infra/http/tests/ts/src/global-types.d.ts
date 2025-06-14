/**
 * Global type declarations for tests.
 * Exposes SimulationScenario and SimulationHttpConfig as global types.
 */

declare global {
  /** Scenario type for SimulationHttpClient tests */
  type SimulationScenario = import('./modes/simulation/simulation-http-client').SimulationScenario;
  /** Configuration type for SimulationHttpClient tests */
  type SimulationHttpConfig = import('./modes/simulation/simulation-http-client').SimulationHttpConfig;
}

export {};
