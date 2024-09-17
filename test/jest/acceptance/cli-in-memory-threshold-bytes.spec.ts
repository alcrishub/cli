import * as os from 'os';
import * as path from 'path';
import { resolve } from 'path';

import { runSnykCLI } from '../util/runSnykCLI';
import { matchers } from 'jest-json-schema';

const projectRoot = resolve(__dirname, '../../..');

expect.extend(matchers);

// For golang implementation only
describe('conditionally write data to disk', () => {
  const projectWithCodeIssues = resolve(
    projectRoot,
    'test/fixtures/sast/with_code_issues',
  );

  const env = {
    // Use an org with consistent ignores enabled - uses golang/native workflow
    SNYK_API: process.env.TEST_SNYK_API_DEV,
    SNYK_TOKEN: process.env.TEST_SNYK_TOKEN_DEV,
    SNYK_LOG_LEVEL: 'trace',
  };

  jest.setTimeout(60000);

  // we don't need to create or clean up the temp dir, GAF takes care of this
  const tempDirName = `tempDir-${Date.now()}`;
  const tempDirPath = path.join(os.tmpdir(), tempDirName);

  describe('when temp dir and threshold are set', () => {
    const tempDirVars = {
      SNYK_TMP_PATH: tempDirPath,
      INTERNAL_IN_MEMORY_THRESHOLD_BYTES: '1',
    };

    it('should write to temp dir if payload is bigger than threshold', async () => {
      const { stderr } = await runSnykCLI(
        `code test ${projectWithCodeIssues} -d`,
        {
          env: {
            ...process.env,
            ...env,
            ...tempDirVars,
          },
        },
      );

      const expectedLogRegexMatchers = [
        /payload is \[]byte, comparing payload size \(([0-9]+) bytes\) to threshold \(1 bytes\)/g,
        /payload location for: did:\/\/[^\s]+ is on disk, reading from disk/g,
      ];

      const expectedLogMessages = [
        'payload is larger than threshold, writing it to disk',
        `Payload written to file: ${tempDirPath}`,
        'payload is on disk, nil payload in memory for cleanup',
        `Deleted temporary directory: ${tempDirPath}`,
      ];

      for (let i = 0; i < expectedLogMessages.length; i++) {
        expect(stderr).toContain(expectedLogMessages[i]);
      }

      for (let i = 0; i < expectedLogRegexMatchers.length; i++) {
        expect(stderr).toMatch(expectedLogRegexMatchers[i]);
      }
    });
  });

  describe('when only threshold is set', () => {
    const tempDirVars = {
      INTERNAL_IN_MEMORY_THRESHOLD_BYTES: '1',
    };

    it('should write to default temp dir if payload is bigger than threshold', async () => {
      const { stderr } = await runSnykCLI(
        `code test ${projectWithCodeIssues} -d`,
        {
          env: {
            ...process.env,
            ...env,
            ...tempDirVars,
          },
        },
      );

      const expectedLogRegexMatchers = [
        /payload is \[]byte, comparing payload size \(([0-9]+) bytes\) to threshold \(1 bytes\)/g,
        /payload location for: did:\/\/[^\s]+ is on disk, reading from disk/g,
      ];

      const expectedLogMessages = [
        'payload is larger than threshold, writing it to disk',
        'Payload written to file:',
        'payload is on disk, nil payload in memory for cleanup',
        'Deleted temporary directory:',
      ];

      for (let i = 0; i < expectedLogMessages.length; i++) {
        expect(stderr).toContain(expectedLogMessages[i]);
      }

      for (let i = 0; i < expectedLogRegexMatchers.length; i++) {
        expect(stderr).toMatch(expectedLogRegexMatchers[i]);
      }
    });
  });

  describe('when temp dir and threshold are NOT set', () => {
    it('should use 512MB as default threshold', async () => {
      const { stderr } = await runSnykCLI(
        `code test ${projectWithCodeIssues} -d`,
        {
          env: {
            ...process.env,
            ...env,
          },
        },
      );

      const expectedLogRegexMatchers =
        /payload is \[]byte, comparing payload size \(([0-9]+) bytes\) to threshold \(536870912 bytes\)/g;

      expect(stderr).toMatch(expectedLogRegexMatchers);
    });
  });

  describe('when feature is disabled', () => {
    const tempDirVars = {
      INTERNAL_IN_MEMORY_THRESHOLD_BYTES: '-1',
    };

    it('should keep payload memory', async () => {
      const { stderr } = await runSnykCLI(
        `code test ${projectWithCodeIssues} -d`,
        {
          env: {
            ...process.env,
            ...env,
            ...tempDirVars,
          },
        },
      );

      const expectedLogMessages =
        'memory threshold feature disabled, keeping payload in memory';

      expect(stderr).toContain(expectedLogMessages);
    });
  });
});
