Feature: The door's key can come through the broker

  The ask, paraphrased, `@decided 2026-11-04`: this plane takes its key through the
  TokenFuse MCP broker, so the broker can put a run's label on the act rather than
  on a name the agent reported.

  What was there before. The broker forwards a call with nothing of the caller's, so
  a plane behind it never sees the header this door reads, and an agent holding the
  key can go round the broker. The key now arrives in the message, written there by
  the broker on the last hop, so the agent holds a handle and never the key.

  Scenario: a call with its key in the message is admitted and attributed
    Given the operator turned this on
    When a call carries a known key in its _meta
    Then it is fetched, and the record names that key's agent
  # @test:TestACredentialInMetaAdmitsTheCallAndNamesItsAgent

  Scenario: nothing changes unless an operator says so
    Given the operator did not turn this on
    When a call carries a known key in its _meta
    Then it is refused at the door, as a call with no credential
  # @test:TestWithTheFlagOffTheEntryIsNotACredential

  Scenario: with this off the door still answers before the body
    Given the operator did not turn this on
    When a caller with no credential sends something that is not JSON
    Then the door refuses it and the parser never speaks
  # @test:TestWithTheFlagOffTheDoorStillRefusesBeforeTheBody

  Scenario: a wrong key is refused, a handle nobody filled in included
    When a call carries an unknown key, a bare handle or nothing in its _meta
    Then it is refused and nothing is fetched
  # @test:TestAWrongKeyInMetaIsRefused

  Scenario: the header wins when both are sent
    When a call carries one key in the header and another in the message
    Then the header's key decides, and a bad header is not rescued by the body
  # @test:TestTheHeaderWinsWhenBothAreSent

  Scenario: leaving out the id is no way past the door
    When a tools/call with no id and no credential arrives
    Then it is refused, because this server dispatches on the method
  # @test:TestACallWithNoIDStillNeedsACredential

  Scenario: the handshake and the listing need no credential behind the broker
    Given the operator turned this on
    When initialize, tools/list or the initialized notification arrive with none
    Then they are answered, because the broker sends them bare and they fetch nothing
  # @test:TestTheHandshakeAndTheListingNeedNoCredentialBehindTheBroker

  Scenario: anything else with no credential is refused
    When a body that is unknown, a batch, two messages or unreadable arrives with none
    Then it is refused and nothing is fetched
  # @test:TestAnythingElseWithNoCredentialIsRefused

  Scenario: a body over the bound carries no credential
    When a call larger than the bound arrives with a known key in it
    Then it is refused at the door
  # @test:TestABodyOverTheBoundCarriesNoCredential

  Scenario: the key stops at the door
    When a call is admitted on a key in its message
    Then neither the fetch nor the answer holds that key
  # @test:TestNothingPastTheDoorHoldsTheKey

  Scenario: what the door leaves behind holds no key
    When the door has read a call that carried its key in the message
    Then the request it hands on still carries the call and no longer the entry
  # @test:TestTheDoorLeavesTheRequestWithNoEntryInIt

  Scenario: the binary reads the switch
    Given the real binary, started with and without the switch
    When tools/list arrives with no credential
    Then it is answered with the switch on and refused with it off
  # @test:TestTheBinaryReadsTheKeyInMetaSwitch
