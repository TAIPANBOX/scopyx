Feature: A fetch through the broker carries the run that asked for it

  The ask, paraphrased from the estate register: a fetch carries the run it was made
  for, so this plane's record joins the rest of that run.

  What was there before. The server was handed one run when the process started, so
  every fetch of a process carried one label, whichever run asked for it. The broker
  now names the run on the last hop, the same header TokenFuse reads from its callers.

  Scenario: each call carries the run it names
    Given one process serving two runs
    When each call names its own run
    Then each fetch carries that run
  # @test:TestEachCallCarriesTheRunItNames

  Scenario: the run reaches the record and the policy plane
    When a call names a run
    Then the record of the fetch carries it, and so does the question to the policy plane
  # @test:TestARunNamedOnACallReachesTheRecordAndThePolicyPlane

  Scenario: a call that names no run keeps the process's
    When a client with no broker in front of it sends no run
    Then the fetch carries the process's run, as it always did
  # @test:TestACallThatNamesNoRunKeepsTheProcessRun

  Scenario: the run travels beside a key in the message
    Given the broker writes the key into the message
    When the same call names a run in the header
    Then the fetch carries that run and the key's agent
  # @test:TestARunArrivesBesideAKeyInTheMessage

  Scenario: a run opens no door
    When a call names a run and presents no credential
    Then the door refuses it and nothing is fetched
  # @test:TestARunHeaderOpensNoDoor

  Scenario: a header that is not a label writes nothing into the record
    When the header holds a space, a control byte, a non-ASCII byte or too many bytes
    Then the fetch carries the process's run
  # @test:TestAHeaderThatIsNoRunLabelIsNotRecorded

  Scenario: no hostile header reaches the record
    When twenty thousand seeded headers arrive
    Then what is recorded is the process's run or one bounded word of printable ASCII
  # @test:TestNoHeaderPutsAnUnprintableByteInTheRecord
