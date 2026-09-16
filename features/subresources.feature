Feature: Every subresource is a question to the policy plane

  A page is a document plus forty requests the caller never named, and the
  chromium backend is the one backend that decides each of them. Until
  2026-09-16 it decided them against the address rules and an allow-set the
  policy plane never sends, so a subresource on an approved page reached any
  public host at all while the record said per_request. Separately, the proxy
  under the browser asked the decider on a context of its own, so nothing the
  fetch had established reached that question.

  @decided 2026-09-16: re-verify the finding against the code and the record
  first, then fix it red first: each subresource host is asked about through
  the fetch's own memo, and a question that cannot be asked is a refusal.

  # @test:TestASubresourceHostThePolicyPlaneRefusesIsDenied
  Scenario: A subresource host the policy plane refuses is denied
    Given a policy plane that refuses tracker.example
    And a fetch with its memo on the context
    When the decider is asked about https://tracker.example/t.css
    Then the verdict is deny_policy
    And the policy plane was asked about exactly that host

  # @test:TestASubresourceThePolicyPlaneAllowsIsAllowedWithItsCheckedAddresses
  Scenario: An allowed subresource is allowed, with the addresses that were checked
    Given a policy plane that allows cdn.example
    When the decider is asked about https://cdn.example/app.js
    Then the verdict is allow
    And the addresses handed back are the ones the decision was made on

  # @test:TestASubresourceIsDecidedOncePerHostNotOncePerRequest
  Scenario: One question per host, not one per request
    Given three subresources on cdn.example in one fetch
    When each is decided
    Then the policy plane was asked once

  # @test:TestAnUnreachablePolicyPlaneRefusesASubresourceAndSaysWhichRefusalItWas
  Scenario: A policy plane that cannot be asked is a refusal that says so
    Given the policy plane has gone away before the page loads
    When the decider is asked about a subresource
    Then the verdict is deny_policy_unreachable, never deny_policy

  # @test:TestASubresourceAskedOutsideAGovernedFetchIsRefused
  Scenario: Outside a governed fetch there is nobody to ask
    Given a context no fetch prepared
    When the decider is asked about a subresource
    Then it is refused as unreachable and the reason names the missing memo

  # @test:TestTheProxyAsksTheDeciderWithTheFetchsOwnContext
  Scenario: The proxy under the browser asks with the fetch's own context
    Given a decider that refuses any question asked without what the fetch established
    And a page with one allowed stylesheet
    When the page is rendered through the proxy
    Then the stylesheet's server is reached

  # @test:TestASubresourceThePolicyPlaneRefusesNeverReachesItsServer
  Scenario: The refused subresource never reaches its server, with a real browser
    Given a page on doc.example with one stylesheet on cdn.example and one on tracker.example
    And a policy plane that refuses tracker.example
    When the page is fetched through the whole plane with the chromium backend
    Then cdn.example's server is reached and tracker.example's server is not
    And the record counts the refused subresource
    And the policy plane was asked about tracker.example
