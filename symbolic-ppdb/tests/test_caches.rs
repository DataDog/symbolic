use symbolic_common::Language;
use symbolic_ppdb::LineInfo;
use symbolic_ppdb::PortablePdb;
use symbolic_ppdb::PortablePdbCache;
use symbolic_ppdb::PortablePdbCacheConverter;
use symbolic_testutils::fixture;

#[test]
fn test_documents() {
    let buf = std::fs::read("tests/fixtures/Documents.pdbx").unwrap();

    let pdb = PortablePdb::parse(&buf).unwrap();

    let mut converter = PortablePdbCacheConverter::new();
    converter.process_portable_pdb(&pdb).unwrap();
    let mut buf = Vec::new();
    converter.serialize(&mut buf).unwrap();

    let _cache = PortablePdbCache::parse(&buf).unwrap();
}

#[test]
fn test_async() {
    let buf = std::fs::read("tests/fixtures/Async.pdbx").unwrap();

    let pdb = PortablePdb::parse(&buf).unwrap();

    let mut converter = PortablePdbCacheConverter::new();
    converter.process_portable_pdb(&pdb).unwrap();
    let mut buf = Vec::new();
    converter.serialize(&mut buf).unwrap();

    let _cache = PortablePdbCache::parse(&buf).unwrap();
}

#[test]
fn test_lookup_first() {
    let buf = std::fs::read("tests/fixtures/Async.pdbx").unwrap();

    let pdb = PortablePdb::parse(&buf).unwrap();

    let mut converter = PortablePdbCacheConverter::new();
    converter.process_portable_pdb(&pdb).unwrap();
    let mut buf = Vec::new();
    converter.serialize(&mut buf).unwrap();

    let cache = PortablePdbCache::parse(&buf).unwrap();

    // Function 5's first surviving sequence point does not start at IL offset 0 (hidden
    // sequence points before it were stripped when the cache was built), so `lookup` at offset 0
    // finds no exact match and, being a "nearest preceding" search, incorrectly falls back into
    // the previous function's range instead of this function's own first range.
    assert_eq!(cache.lookup(5, 0), None);

    // `lookup_first` does not have that failure mode: it searches forward for this function's
    // lowest-offset range instead of backward from a specific offset.
    assert_eq!(
        cache.lookup_first(5),
        Some(LineInfo {
            line: 8,
            file_name: "C:\\Async.cs",
            file_lang: Language::CSharp
        })
    );

    // Function 4 has no sequence points in the cache at all.
    assert_eq!(cache.lookup_first(4), None);
}

#[test]
fn test_integration() {
    let buf = std::fs::read(fixture("windows/portable.pdb")).unwrap();

    let pdb = PortablePdb::parse(&buf).unwrap();

    let mut converter = PortablePdbCacheConverter::new();
    converter.process_portable_pdb(&pdb).unwrap();
    let mut buf = Vec::new();
    converter.serialize(&mut buf).unwrap();

    let cache = PortablePdbCache::parse(&buf).unwrap();

    assert_eq!(
        cache.lookup(7, 10),
        Some(LineInfo {
            line: 81,
            file_name: "/Users/swatinem/Coding/sentry-dotnet/samples/foo/Program.cs",
            file_lang: Language::CSharp
        })
    );

    assert_eq!(
        cache.lookup(5, 6),
        Some(LineInfo {
            line: 37,
            file_name: "/Users/swatinem/Coding/sentry-dotnet/samples/foo/Program.cs",
            file_lang: Language::CSharp
        })
    );

    assert_eq!(
        cache.lookup(3, 0),
        Some(LineInfo {
            line: 30,
            file_name: "/Users/swatinem/Coding/sentry-dotnet/samples/foo/Program.cs",
            file_lang: Language::CSharp
        })
    );

    assert_eq!(
        cache.lookup(2, 0),
        Some(LineInfo {
            line: 25,
            file_name: "/Users/swatinem/Coding/sentry-dotnet/samples/foo/Program.cs",
            file_lang: Language::CSharp
        })
    );

    assert_eq!(
        cache.lookup(1, 45),
        Some(LineInfo {
            line: 20,
            file_name: "/Users/swatinem/Coding/sentry-dotnet/samples/foo/Program.cs",
            file_lang: Language::CSharp
        })
    );
}
