import { describe, it, expect } from 'vitest';
import { classifyRobot } from '../src/lib/sslyze-robot.js';

describe('classifyRobot', () => {
  it('flags a strong oracle as critical', () => {
    expect(classifyRobot('VULNERABLE_STRONG_ORACLE')).toEqual({
      severity: 'critical',
      title: 'ROBOT vulnerable (VULNERABLE_STRONG_ORACLE)',
    });
  });
  it('flags a weak oracle as critical', () => {
    expect(classifyRobot('VULNERABLE_WEAK_ORACLE')).toEqual({
      severity: 'critical',
      title: 'ROBOT vulnerable (VULNERABLE_WEAK_ORACLE)',
    });
  });
  it('downgrades an inconclusive result to low, not critical', () => {
    expect(classifyRobot('UNKNOWN_INCONSISTENT_RESULTS')).toEqual({
      severity: 'low',
      title: 'ROBOT test inconclusive — manual re-test advised',
    });
  });
  it('emits nothing when not vulnerable (no oracle)', () => {
    expect(classifyRobot('NOT_VULNERABLE_NO_ORACLE')).toBeNull();
  });
  it('emits nothing when RSA key exchange is not supported', () => {
    expect(classifyRobot('NOT_VULNERABLE_RSA_NOT_SUPPORTED')).toBeNull();
  });
  it('emits nothing for a missing result', () => {
    expect(classifyRobot(undefined)).toBeNull();
    expect(classifyRobot(null)).toBeNull();
    expect(classifyRobot('')).toBeNull();
  });
});
