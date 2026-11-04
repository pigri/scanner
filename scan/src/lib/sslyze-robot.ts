// Classify sslyze's ROBOT (Return Of Bleichenbacher's Oracle Threat) result into
// a finding severity/title, or null when nothing should be emitted.
//
// sslyze's robot_result enum has five values:
//   VULNERABLE_STRONG_ORACLE        — confirmed, easily exploitable
//   VULNERABLE_WEAK_ORACLE          — confirmed, harder to exploit
//   NOT_VULNERABLE_NO_ORACLE        — tested safe
//   NOT_VULNERABLE_RSA_NOT_SUPPORTED — no RSA key exchange, safe
//   UNKNOWN_INCONSISTENT_RESULTS    — inconclusive; sslyze could not decide

export interface RobotClassification {
  severity: string;
  title: string;
}

export function classifyRobot(robotResult: string | null | undefined): RobotClassification | null {
  if (!robotResult) return null;
  // Only VULNERABLE_STRONG_ORACLE / VULNERABLE_WEAK_ORACLE are confirmed hits.
  if (robotResult.startsWith('VULNERABLE')) {
    return { severity: 'critical', title: `ROBOT vulnerable (${robotResult})` };
  }
  // Inconclusive: sslyze got inconsistent probe responses (load balancer, CDN,
  // jitter) and could not decide. Not a confirmation — surface low for re-test.
  if (robotResult === 'UNKNOWN_INCONSISTENT_RESULTS') {
    return { severity: 'low', title: 'ROBOT test inconclusive — manual re-test advised' };
  }
  // NOT_VULNERABLE_NO_ORACLE / NOT_VULNERABLE_RSA_NOT_SUPPORTED → nothing.
  return null;
}
