Feature: A screenshot request gets a screenshot, and wait_for is waited for

  extract=screenshot and wait_for are frozen names compat/1.0.json promises
  and the browse tool has always accepted. Until 2026-09-16 the chromium
  backend implemented neither: a screenshot request came back as the page's
  HTML with nothing in the fidelity block saying so, and wait_for was carried
  on backend.Request and never read, so navigation waited only for the load
  event. Invariant 5 says a result never claims more than happened, and a
  caller who asked for a screenshot and got HTML is exactly that.

  @decided 2026-09-16: implement both on the chromium backend, red first. A
  screenshot is returned as base64 PNG, bounded by MaxBodyBytes like every
  other extract but refused rather than truncated, since a PNG cut at an
  arbitrary byte offset cannot be decoded. wait_for polls
  document.querySelector for the selector, bounded by the fetch's own
  remaining timeout minus a reserve for the extraction that follows it; a
  selector that never appears is not an error, it is the document coming back
  with the time truncation named. The selector is caller input and reaches
  the evaluated expression as a JSON string literal, never by concatenation,
  so it cannot break out of the call it sits inside. The passthrough backend
  cannot render either: it now refuses extract=screenshot instead of silently
  answering with raw HTML, and its doc comment says plainly that it accepts
  and ignores wait_for, because there is no DOM for a selector to ever appear
  in.

  # @test:TestScreenshotReturnsAPNGBody
  Scenario: A screenshot request returns a base64 PNG body
    Given a page every decision allows, rendered by the chromium backend
    When extract=screenshot is requested
    Then the body decodes from base64 to bytes starting with the PNG magic number

  # @test:TestScreenshotOverTheByteBoundIsRefusedRatherThanTruncated
  Scenario: A screenshot over the byte bound is refused, not truncated
    Given a MaxBodyBytes bound too small for any real screenshot
    When extract=screenshot is requested
    Then the fetch is refused with an error naming the screenshot, not a cut file

  # @test:TestWaitForReturnsTheElementInsertedAfterLoad
  Scenario: wait_for returns the document after the element it names appears
    Given a page whose own script inserts an element 2 seconds after load
    When wait_for names that element's selector
    Then the extracted text contains what the element holds

  # @test:TestWaitForOnASelectorThatNeverAppearsReturnsWithinTheBoundWithTimeTruncation
  Scenario: A selector that never appears returns within the bound, not an error
    Given a page that never grows the selector wait_for names
    When the fetch is made with a short overall timeout
    Then it returns well inside that timeout with the document present
    And the fidelity block's truncated_by is time

  # @test:TestWaitForSelectorWithAQuoteAndParenIsNotAnInjection
  Scenario: A selector holding a quote and a closing paren is not an injection
    Given a wait_for value built to break out of querySelector's string argument
    And a canary server the injected script would reach if it ran
    When the page is fetched
    Then the canary is never reached and the document still comes back

  # @test:TestPassthroughRefusesScreenshotRatherThanReturningHTML
  Scenario: The passthrough backend refuses a screenshot instead of answering with HTML
    Given the passthrough backend, which renders nothing
    When extract=screenshot is requested
    Then the fetch is refused, naming the screenshot, before the server is even asked

  # @test:TestFidelityNamesTheExtractThatWasRequestedDefaultedToHTML
  Scenario: The fidelity block names what was asked for
    Given a fetch with extract set to text, html, screenshot, or left empty
    When the fidelity block is assembled
    Then its extract field is that value, or html when the request left it empty
