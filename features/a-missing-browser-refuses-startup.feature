Feature: A browser path that names nothing refuses startup

  The chromium backend drives a browser the operator installs. A path the
  operator named that is not there is a configuration error, reported when the
  service starts and naming the path, not on the first fetch as a launch
  failure.

  # @test:TestTheChromiumBackendRefusesToStartWithAMissingBrowserPath
  Scenario: SCOPYX_CHROMIUM names a file that does not exist
    Given SCOPYX_BACKEND is chromium and SCOPYX_CHROMIUM names a path with nothing there
    When scopyx starts
    Then it refuses to start, and the error says no browser was found and names the path

  # @test:TestAConfiguredBrowserPathThatIsNotAFileIsRefusedAtConstruction
  Scenario: SCOPYX_CHROMIUM names a directory
    Given the configured browser path is a directory, or a file that is missing
    When the chromium backend is built
    Then it is refused as a missing browser, with the path in the message
