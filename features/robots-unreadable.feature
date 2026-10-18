Feature: An unreadable robots.txt is a decision, and the decision is written down

  A site whose robots.txt cannot be read is allowed by default, because one
  site's outage must not stop an operator's own governed work. That allow used
  to leave no trace: the caveat stayed inside the robots package and the fetch
  did not write it down. Each decision made without a site's rules is now a
  log line naming the destination, never the path or the query.

  Scenario: an unreadable robots.txt allows the fetch, and the allow is written down for each destination
    Given two sites whose robots.txt answers with a server error
    When a page is fetched from each in the default posture
    Then each fetch is allowed and each destination has one allowed line in the log
  # @test:TestAnUnreadableRobotsIsLoggedForEachDestinationWhenAllowed

  Scenario: each fetch to such a site is a decision of its own
    Given a site whose robots.txt cannot be read and a reading that is still cached
    When two pages are fetched from it
    Then the log holds one decision line for each fetch
  # @test:TestEachFetchToAnUnreadableSiteIsLoggedNotOnlyTheFirst

  Scenario: the strict posture refuses, and the refusal is written down
    Given a site whose robots.txt cannot be read and the strict posture
    When a page is fetched from it
    Then the fetch is refused and the log holds a refused line for its destination
  # @test:TestAnUnreadableRobotsIsLoggedWhenStrictRefuses

  Scenario: a readable robots.txt writes no decision line
    Given a site whose robots.txt can be read
    When pages are fetched from it
    Then the rules decide and the log holds no decision line
  # @test:TestAReadableRobotsWritesNoDecisionLine

  Scenario: with robots off nothing is asked and nothing is written
    Given the robots posture is off
    When a page is fetched
    Then no robots.txt is requested and the log holds no decision line
  # @test:TestOffWritesNoDecisionLine
