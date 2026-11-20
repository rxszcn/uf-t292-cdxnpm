/*!
This file is part of CycloneDX generator for NPM projects.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
Copyright (c) OWASP Foundation. All Rights Reserved.
*/

/*
 * Behavior-matrix pinning tests for the PURL assembly and source-determination
 * pure functions. Every assertion below was read from the current snapshot
 * build (`dist/factories.js`, `dist/_helpers.js`); no current behavior is
 * re-interpreted or "corrected". The matrix is organized along the ten
 * required coverage points (three routing branches, three fallback-chain
 * branches, three degraded-input semantics, one sanitization branch).
 */

const { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } = require('node:fs')
const { tmpdir } = require('node:os')
const path = require('node:path')

const { describe, expect, test } = require('@jest/globals')

const {
  isString,
  iterableFilter,
  iterableMap,
  loadJsonFile,
  normalizePackageManifest,
  npmResolvedIgnoreMatcher,
  npmResolvedVcsMatcher,
  setDifference,
  tryRemoveSecretsFromUrl,
  versionCompare,
  versionTuple,
  writeAllSync
} = require('../../dist/_helpers')
const { PackageUrlFactory } = require('../../dist/factories')

const factory = new PackageUrlFactory()

// build a minimal valid PackageData, optionally overriding any field
const packageData = (overrides = {}) => ({
  name: 'alpha',
  version: '1.0.0',
  dependencies: new Set(),
  ...overrides
})

// rendered PURL string, or the literal `undefined` when assembly failed
const purlOf = (data) => factory.makeFromPackageData(data)?.toString()
const purlOfJson = (packageJson) => factory.makeFromPackageJson(packageJson)?.toString()

// base PURL that every qualifier branch in makeFromPackageData starts from
const basePurl = 'pkg:npm/alpha@1.0.0'

describe('factories.PackageUrlFactory', () => {
  // region coverage point 1 — source routing: protocol header case-insensitivity
  describe('source routing — protocol header case-insensitive', () => {
    // matcher level: the `i` flag makes every protocol header match regardless of case
    test.each([
      // purpose, resolved, expected vcs match
      ['lowercase git://', 'git://example.com/a.git', true],
      ['uppercase GIT://', 'GIT://example.com/a.git', true],
      ['mixed-case git+https://', 'GIT+HTTPS://github.com/o/r.git', true],
      ['uppercase .git suffix over https', 'HTTPS://H/O/R.GIT', true],
      ['lowercase .git suffix', 'https://h/o/r.git', true],
      ['lowercase ssh://', 'ssh://git@github.com/o/r.git', true],
      ['mixed-case SsH://', 'SsH://h/r', true]
    ])('vcs matcher %s', (_purpose, resolved, expectedVcs) => {
      expect(npmResolvedVcsMatcher.test(resolved)).toBe(expectedVcs)
    })

    test.each([
      ['lowercase git+https routes to vcs_url',
        'git+https://github.com/o/r.git',
        `${basePurl}?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git`],
      ['uppercase GIT keeps original spelling in vcs_url',
        'GIT://example.com/a.git',
        `${basePurl}?vcs_url=GIT%3A%2F%2Fexample.com%2Fa.git`],
      ['uppercase SSH keeps original spelling in vcs_url',
        'SSH://h/r',
        `${basePurl}?vcs_url=SSH%3A%2F%2Fh%2Fr`]
    ])('assembly %s', (_purpose, resolved, expectedPurl) => {
      expect(purlOf(packageData({ resolved }))).toBe(expectedPurl)
    })
  })
  // endregion

  // region coverage point 2 — source routing: short-form landing spots
  describe('source routing — short-form matcher landing spots', () => {
    test.each([
      // purpose, resolved, vcs matched, expected rendered PURL
      ['bare git: short prefix', 'git:foo', true,
        `${basePurl}?vcs_url=git%3Afoo`],
      ['git+file transport short prefix', 'git+file:///x/r', true,
        `${basePurl}?vcs_url=git%2Bfile%3A%2F%2F%2Fx%2Fr`],
      ['bare ssh: short prefix', 'ssh:foo', true,
        `${basePurl}?vcs_url=ssh%3Afoo`],
      ['.git suffix without fragment', 'https://h/o/r.git', true,
        `${basePurl}?vcs_url=https%3A%2F%2Fh%2Fo%2Fr.git`],
      ['.git suffix with fragment', 'https://h/o/r.git#abc', true,
        `${basePurl}?vcs_url=https%3A%2F%2Fh%2Fo%2Fr.git%23abc`],
      ['plain https without .git is neither vcs nor registry -> download_url',
        'https://github.com/o/r', false,
        `${basePurl}?download_url=https%3A%2F%2Fgithub.com%2Fo%2Fr`],
      ['default registry URL -> no qualifier at all',
        'https://registry.npmjs.org/alpha/-/alpha-1.0.0.tgz', false,
        basePurl]
    ])('%s', (_purpose, resolved, expectedVcs, expectedPurl) => {
      expect(npmResolvedVcsMatcher.test(resolved)).toBe(expectedVcs)
      expect(purlOf(packageData({ resolved }))).toBe(expectedPurl)
    })
  })
  // endregion

  // region coverage point 3 — source routing: ignore forms
  describe('source routing — ignore forms', () => {
    test.each([
      // purpose, resolved, expected ignore match
      ['lowercase ignore: prefix', 'ignore:whatever', true],
      ['uppercase IGNORE: prefix', 'IGNORE:x', true],
      ['lowercase file: prefix', 'file:./local.tgz', true],
      ['uppercase FILE: prefix', 'FILE://host/x', true],
      ['regular https is not ignored', 'https://example.com/a.tgz', false]
    ])('ignore matcher %s', (_purpose, resolved, expectedIgnore) => {
      expect(npmResolvedIgnoreMatcher.test(resolved)).toBe(expectedIgnore)
    })

    test.each([
      // purpose, resolved — every ignored form suppresses all qualifiers
      ['ignore: suppresses qualifiers', 'ignore:whatever'],
      ['IGNORE: suppresses qualifiers', 'IGNORE:x'],
      ['file: suppresses qualifiers', 'file:./local.tgz'],
      ['FILE: suppresses qualifiers', 'FILE://host/x'],
      // outer ignore check short-circuits before the inner vcs matcher is consulted
      ['file: + .git still ignored despite vcs shape', 'file:foo.git']
    ])('assembly %s', (_purpose, resolved) => {
      const purl = factory.makeFromPackageData(packageData({ resolved }))
      expect(purl.toString()).toBe(basePurl)
      // PackageURL normalizes the factory's empty `{}` qualifiers object to `undefined`
      expect(purl.qualifiers).toBeUndefined()
    })

    test('a non-string resolved is skipped without any qualifier', () => {
      const purl = factory.makeFromPackageData(packageData({ resolved: 12345 }))
      expect(purl.toString()).toBe(basePurl)
      expect(purl.qualifiers).toBeUndefined()
    })
  })
  // endregion

  // region coverage point 4 — fallback chain: tarball address degradation
  describe('makeFromPackageJson fallback chain — tarball degradation', () => {
    test.each([
      // purpose, dist.tarball, expected rendered PURL
      ['non-registry tarball -> download_url',
        'https://artifacts.example/beta-2.0.0.tgz',
        'pkg:npm/beta@2.0.0?download_url=https%3A%2F%2Fartifacts.example%2Fbeta-2.0.0.tgz'],
      ['registry tarball -> no qualifier',
        'https://registry.npmjs.org/beta/-/beta-2.0.0.tgz',
        'pkg:npm/beta@2.0.0'],
      // length threshold is strictly `> 5`: a 5-char string falls through to repository
      ['5-char tarball degraded, repository object wins -> vcs_url',
        'a.tgz',
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git'],
      ['6-char tarball still qualifies -> download_url',
        'ab.tgz',
        'pkg:npm/beta@2.0.0?download_url=ab.tgz'],
      ['non-string numeric tarball degraded to repository branch -> vcs_url',
        1234567,
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git'],
      ['missing tarball falls back to repository object -> vcs_url',
        undefined,
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git']
    ])('%s', (_purpose, tarball, expectedPurl) => {
      const actual = purlOfJson({
        name: 'beta',
        version: '2.0.0',
        dist: { tarball },
        repository: { url: 'git+https://github.com/o/r.git' }
      })
      expect(actual).toBe(expectedPurl)
    })
  })
  // endregion

  // region coverage point 5 — fallback chain: string-form repository declaration is skipped
  describe('makeFromPackageJson fallback chain — string repository skipped', () => {
    test.each([
      // purpose, repository value, expected rendered PURL
      ['string repository is not an object -> skipped, no qualifier',
        'git+https://github.com/o/r.git',
        'pkg:npm/beta@2.0.0'],
      ['null repository is not an object -> skipped',
        null,
        'pkg:npm/beta@2.0.0'],
      ['object repository with unparsable url -> error swallowed, no qualifier',
        { url: 'not a url' },
        'pkg:npm/beta@2.0.0'],
      ['object repository without url -> URL constructor throws, no qualifier',
        {},
        'pkg:npm/beta@2.0.0'],
      ['valid object repository -> vcs_url',
        { url: 'git+https://github.com/o/r.git' },
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git']
    ])('%s', (_purpose, repository, expectedPurl) => {
      const actual = purlOfJson({ name: 'beta', version: '2.0.0', repository })
      expect(actual).toBe(expectedPurl)
    })
  })
  // endregion

  // region coverage point 6 — fallback chain: directory encoded into url fragment
  describe('makeFromPackageJson fallback chain — directory encoded as fragment', () => {
    test.each([
      // purpose, repository, expected rendered PURL
      ['string directory becomes the url hash',
        { url: 'git+https://github.com/o/r.git', directory: 'packages/beta' },
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git%23packages%2Fbeta'],
      ['non-string directory is ignored, no hash appended',
        { url: 'git+https://github.com/o/r.git', directory: 42 },
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git'],
      ['missing directory leaves the repository url untouched',
        { url: 'git+https://github.com/o/r.git' },
        'pkg:npm/beta@2.0.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fo%2Fr.git']
    ])('%s', (_purpose, repository, expectedPurl) => {
      const actual = purlOfJson({ name: 'beta', version: '2.0.0', repository })
      expect(actual).toBe(expectedPurl)
    })
  })
  // endregion

  // region coverage point 7 — degraded input: missing name throws
  describe('degraded input — missing name throws', () => {
    test.each([
      // purpose, input for makeFromPackageData
      ['undefined data', undefined],
      ['null data', null],
      ['data object without name', packageData({ name: undefined })]
    ])('makeFromPackageData %s', (_purpose, data) => {
      // current behavior: name access/`startsWith` happens before the try/catch,
      // so the TypeError propagates instead of being converted to `undefined`
      expect(() => factory.makeFromPackageData(data)).toThrow(TypeError)
    })

    test('makeFromPackageJson without name throws TypeError from startsWith', () => {
      expect(() => factory.makeFromPackageJson({ version: '1.0.0' })).toThrow(TypeError)
    })

    test.each([
      // an empty name is accepted by access but rejected by PackageURL -> caught -> undefined
      ['empty name in PackageData', () => purlOf(packageData({ name: '' }))],
      ['empty name in packageJson', () => purlOfJson({ name: '', version: '1.0.0' })]
    ])('%s', (_purpose, call) => {
      expect(call()).toBeUndefined()
    })
  })
  // endregion

  // region coverage point 8 — degraded input: empty version tuples
  describe('degraded input — empty version tuple semantics', () => {
    test.each([
      // purpose, input string, expected frozen tuple
      ['empty string splits to single zero', '', Object.freeze([0])],
      ['double dot yields an inner zero element', '1..3', Object.freeze([1, 0, 3])],
      ['regular dotted string maps to numbers', '1.2.3', Object.freeze([1, 2, 3])]
    ])('versionTuple %s', (_purpose, value, expected) => {
      const actual = versionTuple(value)
      expect(actual).toEqual(expected)
      expect(Object.isFrozen(actual)).toBe(true)
    })

    test.each([
      // purpose, version in PackageData, expected rendered PURL
      ['missing version -> undefined, PURL without @version', undefined, 'pkg:npm/alpha'],
      ['null version -> undefined via isString guard', null, 'pkg:npm/alpha'],
      ['numeric version -> undefined via isString guard', 42, 'pkg:npm/alpha'],
      ['string version is preserved', '1.2.3', 'pkg:npm/alpha@1.2.3']
    ])('makeFromPackageData %s', (_purpose, version, expectedPurl) => {
      expect(purlOf(packageData({ version }))).toBe(expectedPurl)
    })

    test('makeFromPackageJson passes a numeric version straight through and assembly fails -> undefined', () => {
      // note the asymmetry: makeFromPackageJson has no isString guard, and
      // PackageURL rejects non-string versions with PurlError, which is caught
      expect(purlOfJson({ name: 'beta', version: 7 })).toBeUndefined()
    })
  })
  // endregion

  // region coverage point 9 — degraded input: non-numeric version segment comparison
  describe('degraded input — non-numeric segment comparison', () => {
    test.each([
      // purpose, tuple a, tuple b, expected result
      ['two empty tuples are equal', [], [], 0],
      ['empty tuple loses to a populated one', [], [1], -1],
      ['populated tuple beats an empty one', [1], [], 1],
      ['NaN segment treated as zero -> equal', versionTuple('1.x.3'), [1, 0, 3], 0],
      ['NaN segment aligned with missing zero -> equal', versionTuple('1.x'), [1, 0, 0], 0],
      ['NaN segment loses to a positive number', versionTuple('1.2.x'), [1, 2, 1], -1],
      ['missing trailing segment defaults to zero -> equal', [0], [0, 0, 0], 0],
      ['shorter tuple loses when the other has a positive tail', [0], [0, 0, 1], -1]
    ])('%s', (_purpose, a, b, expected) => {
      expect(versionCompare(a, b)).toBe(expected)
    })

    test('a non-numeric segment materializes as NaN, not as a parsed number', () => {
      const tuple = versionTuple('1.x.3')
      expect(Number.isNaN(tuple[1])).toBe(true)
    })
  })
  // endregion
})

describe('_helpers', () => {
  // region coverage point 10 — source sanitization: parse failure returns input unchanged
  describe('tryRemoveSecretsFromUrl', () => {
    test.each([
      // purpose, input, expected output
      ['unparsable text returned as-is', 'not a url', 'not a url'],
      ['empty string returned as-is', '', ''],
      ['bare colon sequence returned as-is', '::::', '::::'],
      // positive control proving the success branch strips only the password
      ['valid url has its password removed but user kept',
        'https://user:secret@registry.example.com/a/-/a-1.0.0.tgz',
        'https://user@registry.example.com/a/-/a-1.0.0.tgz'],
      ['valid url without credentials is unchanged',
        'https://registry.example.com/a-1.0.0.tgz',
        'https://registry.example.com/a-1.0.0.tgz']
    ])('%s', (_purpose, input, expected) => {
      expect(tryRemoveSecretsFromUrl(input)).toBe(expected)
    })
  })
  // endregion

  // remaining exported helpers: pin current behavior so both target files keep
  // full function coverage under the acceptance c8 invocation
  describe('isString', () => {
    test.each([
      ['string', 'a', true],
      ['number', 1, false],
      ['null', null, false],
      ['undefined', undefined, false]
    ])('%s', (_purpose, value, expected) => {
      expect(isString(value)).toBe(expected)
    })
  })

  describe('iterable helpers and setDifference', () => {
    test('iterableMap maps lazily', () => {
      expect([...iterableMap([1, 2, 3], (x) => x * 2)]).toEqual([2, 4, 6])
    })
    test('iterableFilter filters lazily', () => {
      expect([...iterableFilter([1, 2, 3, 4], (x) => x % 2 === 0)]).toEqual([2, 4])
    })
    test.each([
      ['non-empty difference', new Set([1, 2, 3]), new Set([2]), [1, 3]],
      ['empty difference', new Set(), new Set([1]), []]
    ])('%s', (_purpose, s1, s2, expected) => {
      expect([...setDifference(s1, s2)]).toEqual(expected)
    })
  })

  describe('loadJsonFile and writeAllSync', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'cdxnpm-spec-'))

    test('loadJsonFile parses an existing json file', () => {
      const file = path.join(dir, 'p.json')
      writeFileSync(file, JSON.stringify({ name: 'x', v: 1 }))
      expect(loadJsonFile(file)).toEqual({ name: 'x', v: 1 })
    })

    test('loadJsonFile forwards ENOENT for a missing file', () => {
      expect(() => loadJsonFile(path.join(dir, 'missing.json'))).toThrow(
        expect.objectContaining({ code: 'ENOENT' })
      )
    })

    test('writeAllSync writes the full buffer and returns its byte length', async () => {
      const file = path.join(dir, 'out.txt')
      const fd = openSync(file, 'w')
      const written = await writeAllSync(fd, 'hello-write')
      closeSync(fd)
      expect(written).toBe(11)
      expect(readFileSync(file, 'utf8')).toBe('hello-write')
    })

    test('teardown temp dir', () => {
      rmSync(dir, { recursive: true, force: true })
      expect(true).toBe(true)
    })
  })

  describe('normalizePackageManifest', () => {
    test('trims an original string version and expands shorthand repository', () => {
      const manifest = { name: 'pkg', version: '  1.2.3  ', repository: 'github:o/r' }
      normalizePackageManifest(manifest)
      expect(manifest.version).toBe('1.2.3')
      expect(manifest.repository).toEqual({
        type: 'git',
        url: 'git+https://github.com/o/r.git'
      })
    })

    test('keeps a clean semver version as a string', () => {
      const manifest = { name: 'p2', version: '0.0.0' }
      normalizePackageManifest(manifest)
      expect(manifest.version).toBe('0.0.0')
      expect(typeof manifest.version).toBe('string')
    })
  })
})
