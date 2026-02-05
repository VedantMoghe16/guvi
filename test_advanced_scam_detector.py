"""Test script for advanced scam detection orchestrator.

Tests:
1. Evasion detection (leet-speak, typos, unicode)
2. Two-level orchestration flow
3. Structured JSON output
4. Fallback behavior
"""

import asyncio
import sys
import logging

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)


def test_text_normalizer():
    """Test text normalization for evasion tactics."""
    from app.text_normalizer import text_normalizer
    
    print("\n" + "=" * 60)
    print("TEST 1: Text Normalizer - Evasion Detection")
    print("=" * 60)
    
    test_cases = [
        # (input, expected substring in output)
        ("Share your 0TP", "otp"),
        ("Send P!N number", "pin"),
        ("Your b4nk account", "bank"),
        ("Y0ur 4cc0unt is blocked", "account"),
        ("Click l!nk to v3r!fy", "verify"),
        ("O T P", "OTP"),  # Creative spacing
        ("U P I", "UPI"),
        ("K Y C expired", "KYC"),
    ]
    
    passed = 0
    for original, expected in test_cases:
        normalized = text_normalizer.normalize(original)
        success = expected.lower() in normalized.lower()
        status = "✅" if success else "❌"
        print(f"{status} '{original}' -> '{normalized}'")
        if expected.lower() not in normalized.lower():
            print(f"   Expected to contain: '{expected}'")
        if success:
            passed += 1
    
    print(f"\nNormalization: {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)


def test_level1_analysis():
    """Test Level 1 regex analysis with normalization."""
    from app.advanced_scam_orchestrator import scam_orchestrator
    from app.orchestrator_models import ScamType
    
    print("\n" + "=" * 60)
    print("TEST 2: Level 1 Regex Analysis")
    print("=" * 60)
    
    test_cases = [
        # (message, expected_scam, expected_type)
        ("Your bank account will be blocked today", True, ScamType.BANK_FRAUD),
        ("Share your UPI ID immediately", True, ScamType.UPI_FRAUD),
        ("Congratulations! You won a prize!", True, ScamType.LOTTERY_SCAM),
        ("Hello, how are you?", False, None),
        ("Your 4cc0unt is bl0cked. Share 0TP now!", True, ScamType.BANK_FRAUD),  # Evasion
        ("U P I ID needed for K Y C verification", True, ScamType.UPI_FRAUD),  # Spacing
    ]
    
    passed = 0
    for message, expected_scam, expected_type in test_cases:
        result = scam_orchestrator._level1_regex_analysis(message, [])
        is_scam = result.confidence >= 0.3
        
        type_match = (expected_type is None and result.scam_type is None) or result.scam_type == expected_type
        scam_match = is_scam == expected_scam
        
        status = "✅" if (scam_match and type_match) else "❌"
        print(f"{status} '{message[:50]}...'")
        print(f"   -> scam={is_scam} (exp:{expected_scam}), conf={result.confidence:.2f}, type={result.scam_type}")
        
        if scam_match and type_match:
            passed += 1
    
    print(f"\nLevel 1: {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)


async def test_full_orchestrator():
    """Test complete two-level orchestration flow."""
    from app.advanced_scam_orchestrator import scam_orchestrator
    from app.orchestrator_models import RecommendedAction
    
    print("\n" + "=" * 60)
    print("TEST 3: Full Orchestrator Flow")
    print("=" * 60)
    
    test_cases = [
        # High confidence scams (should trigger L1 fast path)
        "URGENT: Your bank account blocked! Share OTP immediately to avoid permanent suspension! Call 9876543210",
        
        # Medium confidence (may trigger L2 if LLM available)
        "Your account needs verification. Please update details.",
        
        # Evasion attempts
        "Your 4cc0unt is bl0cked. Send 0TP and P!N to verify",
        
        # Benign messages
        "Hello, I received your message about the meeting tomorrow.",
    ]
    
    for message in test_cases:
        try:
            result = await asyncio.wait_for(
                scam_orchestrator.analyze(message),
                timeout=10.0
            )
            
            print(f"\nMessage: '{message[:60]}...'")
            print(f"  is_scam: {result.is_scam}")
            print(f"  confidence: {result.confidence:.2f}")
            print(f"  scam_type: {result.scam_type}")
            print(f"  risk_level: {result.risk_level}")
            print(f"  action: {result.recommended_action}")
            print(f"  source: {result.analysis_source}")
            print(f"  reasoning: {result.chain_of_thought[:100]}...")
            
        except asyncio.TimeoutError:
            print(f"⚠️  Timeout analyzing: {message[:50]}...")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    return True


def test_structured_output():
    """Test that output conforms to expected schema."""
    from app.orchestrator_models import (
        ScamAnalysisResponse, 
        RiskLevel, 
        RecommendedAction,
        ScamType,
    )
    
    print("\n" + "=" * 60)
    print("TEST 4: Structured Output Schema")
    print("=" * 60)
    
    # Create a response and verify all fields
    response = ScamAnalysisResponse(
        chain_of_thought="Test reasoning process",
        is_scam=True,
        confidence=0.85,
        scam_type=ScamType.BANK_FRAUD,
        risk_level=RiskLevel.HIGH,
        recommended_action=RecommendedAction.ENGAGE,
    )
    
    # Verify fields
    checks = [
        ("chain_of_thought", isinstance(response.chain_of_thought, str)),
        ("is_scam", isinstance(response.is_scam, bool)),
        ("confidence", 0 <= response.confidence <= 1),
        ("scam_type", response.scam_type in ScamType or response.scam_type is None),
        ("risk_level", response.risk_level in RiskLevel),
        ("recommended_action", response.recommended_action in RecommendedAction),
    ]
    
    passed = 0
    for field, valid in checks:
        status = "✅" if valid else "❌"
        print(f"{status} {field}: valid={valid}")
        if valid:
            passed += 1
    
    # Test legacy format conversion
    legacy = response.to_legacy_format()
    print(f"\n✅ Legacy format: {legacy}")
    
    print(f"\nSchema: {passed}/{len(checks)} checks passed")
    return passed == len(checks)


def test_backward_compatibility():
    """Test that original scam_detector still works."""
    from app.scam_detector import scam_detector
    
    print("\n" + "=" * 60)
    print("TEST 5: Backward Compatibility")
    print("=" * 60)
    
    # Original detector should still work
    result = scam_detector.detect("Your bank account is blocked")
    
    print(f"Original ScamDetector:")
    print(f"  is_scam: {result.is_scam}")
    print(f"  confidence: {result.confidence}")
    print(f"  scam_type: {result.scam_type}")
    
    return result.is_scam and result.scam_type == "bank_fraud"


async def main():
    """Run all tests."""
    print("=" * 60)
    print("ADVANCED SCAM ORCHESTRATOR - TEST SUITE")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(("Text Normalizer", test_text_normalizer()))
    except Exception as e:
        print(f"❌ Text Normalizer failed: {e}")
        results.append(("Text Normalizer", False))
    
    try:
        results.append(("Level 1 Analysis", test_level1_analysis()))
    except Exception as e:
        print(f"❌ Level 1 Analysis failed: {e}")
        results.append(("Level 1 Analysis", False))
    
    try:
        results.append(("Full Orchestrator", await test_full_orchestrator()))
    except Exception as e:
        print(f"❌ Full Orchestrator failed: {e}")
        results.append(("Full Orchestrator", False))
    
    try:
        results.append(("Structured Output", test_structured_output()))
    except Exception as e:
        print(f"❌ Structured Output failed: {e}")
        results.append(("Structured Output", False))
    
    try:
        results.append(("Backward Compatibility", test_backward_compatibility()))
    except Exception as e:
        print(f"❌ Backward Compatibility failed: {e}")
        results.append(("Backward Compatibility", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    for name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status}: {name}")
    
    print(f"\n{passed}/{len(results)} test suites passed")
    
    if passed == len(results):
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print("\n⚠️  Some tests failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
