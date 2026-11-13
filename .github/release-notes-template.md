`<VERSION>` is the Deep.BI build of Apache Druid <UPSTREAM>. <One or two sentences on the changes that matter most, and who they affect.>

## Improvements

- Add <improvement>. <Why it matters, in one sentence.> <What it does once turned on, in one sentence.> [[druid#<N>](https://github.com/apache/druid/pull/<N>)] or [#<N>]
  - Turn it on with `<druid.property>` (<service>, default `<value>`). <Other settings in the same format.>
  - <The main trade-off or limit, if there is one.>
  - <Who or what it applies to.>

## Bug fixes

- Fix <symptom the user saw>. <When it happened.> <What happens now.> [[druid#<N>](https://github.com/apache/druid/pull/<N>)] or [#<N>]

## Security fixes

- Upgrade <library> to <version>. [CVE-<YYYY-NNNNN>](https://nvd.nist.gov/vuln/detail/CVE-<YYYY-NNNNN>)

## Known issues

- <Problem still open in this release, and the workaround if there is one.>

## Upgrade notes

- <Changed default, required setting, mixed-version limit or anything else to act on before upgrading.>

**Note:** This release includes all fixes and improvements from previous `<RELEASE_SERIES>` releases ([full diff from upstream <UPSTREAM>](https://github.com/apache/druid/compare/druid-<UPSTREAM>...deep-bi:druid:v<VERSION>)).