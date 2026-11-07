use broker_now_wire::{NowSectionAvailability, NowSnapshotData, NowSnapshotDataError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::num::NonZeroUsize;

const PROJECT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const TASK: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const SESSION: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAX";
const MEMORY: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAY";
const ACTOR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAZ";
fn available(items: Value) -> Value {
    let total = items.as_array().unwrap().len();
    json!({"availability":"available","items":items,"total":total,"has_more":false,"error":null})
}
fn absent() -> Value {
    json!({"availability":"no_corpus","items":[],"total":0,"has_more":false,"error":null})
}
fn valid() -> Value {
    let actor = ACTOR;
    json!({
        "project_id":PROJECT,"generated_at":"1000000",
        "sections":{
            "tasks":available(json!([{"id":TASK,"session_id":SESSION,"title":"Task",
                "owner":actor,"lease_expires_at":"2000000","updated_at":"1000000"}])),
            "sessions":available(json!([{"id":SESSION,"title":"Session","owner":actor,
                "lease_expires_at":"2000000","updated_at":"1000000",
                "completed_tasks":1,"total_tasks":2}])),
            "memories":available(json!([{"id":MEMORY,"title":" memory ",
                "updated_by":actor,"updated_at":"1000000"}])),
            "knowledge":available(json!([{"slug":"known","title":"","updated_at":"-1"},
                {"slug":"unknown","title":"Unknown time","updated_at":null}]))
        }
    })
}
fn decode(value: &Value) -> Result<NowSnapshotData, NowSnapshotDataError> {
    let bytes = serde_json::to_vec(value).unwrap();
    NowSnapshotData::decode(&bytes, NonZeroUsize::new(bytes.len()).unwrap())
}
fn invalid(value: &Value) {
    assert_eq!(
        decode(value).unwrap_err(),
        NowSnapshotDataError::InvalidData
    );
}

#[test]
fn exact_allowlist_roundtrip_getters_and_redacted_models() {
    let wire = valid();
    let data = decode(&wire).unwrap();
    assert_eq!(data.project_id(), PROJECT);
    assert_eq!(data.generated_at(), "1000000");
    let sections = data.sections();
    let tasks = sections.tasks();
    assert_eq!(tasks.availability(), NowSectionAvailability::Available);
    assert_eq!(tasks.total(), Some(1));
    assert_eq!(tasks.has_more(), Some(false));
    assert_eq!(tasks.error(), None);
    let row = &tasks.items()[0];
    assert_eq!(row.id(), TASK);
    assert_eq!(row.session_id(), SESSION);
    assert_eq!(row.title(), "Task");
    assert_eq!(row.owner(), ACTOR);
    assert_eq!(row.lease_expires_at(), "2000000");
    assert_eq!(row.updated_at(), "1000000");
    let session = &sections.sessions().items()[0];
    assert_eq!(session.id(), SESSION);
    assert_eq!(session.title(), "Session");
    assert_eq!(session.owner(), ACTOR);
    assert_eq!(session.lease_expires_at(), "2000000");
    assert_eq!(session.updated_at(), "1000000");
    assert_eq!(session.completed_tasks(), &1);
    assert_eq!(session.total_tasks(), &2);
    let memory = &sections.memories().items()[0];
    assert_eq!(memory.id(), MEMORY);
    assert_eq!(memory.title(), " memory ");
    assert_eq!(memory.updated_by(), ACTOR);
    assert_eq!(memory.updated_at(), "1000000");
    let knowledge = sections.knowledge().items();
    assert_eq!(knowledge[0].slug(), "known");
    assert_eq!(knowledge[0].title(), "");
    assert_eq!(knowledge[0].updated_at(), Some("-1"));
    assert_eq!(knowledge[1].updated_at(), None);
    assert_eq!(serde_json::to_value(&data).unwrap(), wire);
    for rendered in [
        format!("{data:?}"),
        format!("{sections:?}"),
        format!("{tasks:?}"),
        format!("{row:?}"),
        format!("{session:?}"),
        format!("{memory:?}"),
        format!("{:?}", knowledge[0]),
    ] {
        assert!(!rendered.contains(PROJECT));
        assert!(!rendered.contains(ACTOR));
        assert!(!rendered.contains("2000000"));
    }
    assert!(std::error::Error::source(&NowSnapshotDataError::InvalidData).is_none());
}

fn object_paths(value: &Value, path: String, result: &mut Vec<String>) {
    match value {
        Value::Object(fields) => {
            result.push(path.clone());
            for (key, field) in fields {
                object_paths(field, format!("{path}/{key}"), result);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                object_paths(item, format!("{path}/{index}"), result);
            }
        }
        _ => {}
    }
}
#[test]
fn every_field_is_required_unknown_and_duplicate_fields_fail_at_every_level() {
    let wire = valid();
    let mut paths = vec![];
    object_paths(&wire, String::new(), &mut paths);
    let json = serde_json::to_string(&wire).unwrap();
    for path in paths {
        let object = wire.pointer(&path).unwrap().as_object().unwrap();
        for (field, value) in object {
            let mut missing = wire.clone();
            missing
                .pointer_mut(&path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(decode(&missing).is_err(), "missing {path}/{field}");
            let original_object = serde_json::to_string(object).unwrap();
            let duplicate_pair = format!("{}:{}", serde_json::to_string(field).unwrap(), value);
            let duplicated = format!("{{{duplicate_pair},{}", &original_object[1..]);
            let input = json.replacen(&original_object, &duplicated, 1);
            assert_ne!(json, input);
            assert!(
                NowSnapshotData::decode(input.as_bytes(), NonZeroUsize::new(input.len()).unwrap())
                    .is_err(),
                "duplicate {path}/{field}"
            );
        }
        let mut extra = wire.clone();
        extra
            .pointer_mut(&path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("source".into(), json!("private"));
        invalid(&extra);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishCommand {
    op: String,
    snapshot: NowSnapshotData,
}
#[test]
fn nested_deserialize_validates_without_a_value_intermediate_and_budget_is_exact() {
    let snapshot = serde_json::to_string(&valid()).unwrap();
    let command = format!(r#"{{"op":"publish","snapshot":{snapshot}}}"#);
    let data: PublishCommand = serde_json::from_str(&command).unwrap();
    assert_eq!(data.op, "publish");
    assert_eq!(data.snapshot.project_id(), PROJECT);
    let duplicate = command.replace(
        r#""generated_at":"1000000""#,
        r#""generated_at":"1000000","generated_at":"1000000""#,
    );
    assert_ne!(command, duplicate);
    assert!(serde_json::from_str::<PublishCommand>(&duplicate).is_err());
    let semantically_invalid = command.replace(r#""total":1"#, r#""total":5"#);
    assert!(serde_json::from_str::<PublishCommand>(&semantically_invalid).is_err());
    let bytes = snapshot.as_bytes();
    assert!(NowSnapshotData::decode(bytes, NonZeroUsize::new(bytes.len()).unwrap()).is_ok());
    assert_eq!(
        NowSnapshotData::decode(bytes, NonZeroUsize::new(bytes.len() - 1).unwrap()).unwrap_err(),
        NowSnapshotDataError::ReadLimitExceeded
    );
    for bad in [b"null".as_slice(), b"[]", b"{}", b"\xff", b"true", b"0"] {
        assert_eq!(
            NowSnapshotData::decode(bad, NonZeroUsize::new(100).unwrap()).unwrap_err(),
            NowSnapshotDataError::InvalidData
        );
    }
    for suffix in [" true", "{}", "x"] {
        let bad = format!("{snapshot}{suffix}");
        assert_eq!(
            NowSnapshotData::decode(bad.as_bytes(), NonZeroUsize::new(bad.len()).unwrap())
                .unwrap_err(),
            NowSnapshotDataError::InvalidData
        );
    }
}

#[test]
fn availability_nulls_and_complete_top_twenty_are_enforced() {
    for section in ["tasks", "sessions", "memories", "knowledge"] {
        for code in [
            "forbidden",
            "unavailable",
            "invalid_data",
            "limit_exceeded",
            "counts_unavailable",
        ] {
            let mut value = valid();
            value["sections"][section] = json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":code});
            assert!(decode(&value).is_ok());
            for (field, bad) in [
                ("total", json!(0)),
                ("has_more", json!(false)),
                ("error", Value::Null),
                ("items", json!([{}])),
                ("error", json!("sql_error")),
            ] {
                let mut invalid_value = value.clone();
                invalid_value["sections"][section][field] = bad;
                invalid(&invalid_value);
            }
        }
        let mut value = valid();
        value["sections"][section] = absent();
        assert!(decode(&value).is_ok());
        value["sections"][section]["availability"] = json!("available");
        assert!(decode(&value).is_ok());
        for bad in [
            json!(-1),
            json!(1.0),
            json!(5),
            json!(9_007_199_254_740_992_u64),
            Value::Null,
        ] {
            let mut changed = value.clone();
            changed["sections"][section]["total"] = bad;
            invalid(&changed);
        }
        let mut changed = value.clone();
        changed["sections"][section]["total"] = json!(5);
        changed["sections"][section]["has_more"] = json!(true);
        invalid(&changed);
    }
    let mut value = valid();
    let mut rows = vec![];
    for n in 1..=20 {
        let mut row = value["sections"]["tasks"]["items"][0].clone();
        row["id"] = json!(ulid::Ulid::from(n as u128).to_string());
        rows.push(row);
    }
    value["sections"]["tasks"] = available(json!(rows));
    assert!(decode(&value).is_ok());
    for total in [21, 9_007_199_254_740_991_u64] {
        value["sections"]["tasks"]["total"] = json!(total);
        value["sections"]["tasks"]["has_more"] = json!(true);
        assert!(decode(&value).is_ok());
    }
    let mut short = value.clone();
    short["sections"]["tasks"]["items"]
        .as_array_mut()
        .unwrap()
        .pop();
    invalid(&short);
    let mut extra = value.clone();
    let row = extra["sections"]["tasks"]["items"][0].clone();
    extra["sections"]["tasks"]["items"]
        .as_array_mut()
        .unwrap()
        .push(row);
    invalid(&extra);
}

#[test]
fn canonical_ids_titles_slugs_actors_and_counter_precision() {
    for path in [
        "/project_id",
        "/sections/tasks/items/0/id",
        "/sections/tasks/items/0/session_id",
        "/sections/sessions/items/0/id",
        "/sections/memories/items/0/id",
    ] {
        for bad in [
            "",
            "00000000000000000000000000",
            "01arz3ndektsv4rrffq69g5fav",
            "tsk-short",
            "81ARZ3NDEKTSV4RRFFQ69G5FAV",
        ] {
            let mut value = valid();
            *value.pointer_mut(path).unwrap() = json!(bad);
            invalid(&value);
        }
    }
    for path in [
        "/sections/tasks/items/0/title",
        "/sections/sessions/items/0/title",
    ] {
        for bad in ["", " ", " leading", "trailing "] {
            let mut v = valid();
            *v.pointer_mut(path).unwrap() = json!(bad);
            invalid(&v);
        }
    }
    for bad in ["", " \n\t"] {
        let mut v = valid();
        v["sections"]["memories"]["items"][0]["title"] = json!(bad);
        invalid(&v);
    }
    for path in [
        "/sections/tasks/items/0/owner",
        "/sections/sessions/items/0/owner",
        "/sections/memories/items/0/updated_by",
    ] {
        for bad in [
            String::new(),
            ACTOR.to_lowercase(),
            ACTOR[..25].to_owned(),
            format!("{ACTOR}0"),
            format!(" {ACTOR}"),
            format!("{ACTOR} "),
            "8ZZZZZZZZZZZZZZZZZZZZZZZZZ".into(),
            "IIIIIIIIIIIIIIIIIIIIIIIIII".into(),
            ACTOR.replacen('0', "O", 1),
            "0000000000000000000000000I".into(),
            "a".repeat(63),
            "a".repeat(64),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "issuer|publisher".into(),
        ] {
            let mut v = valid();
            *v.pointer_mut(path).unwrap() = json!(bad);
            invalid(&v);
        }
    }
    for bad in ["", "..hidden", "a/b", "a\\b", "a\n"] {
        let mut v = valid();
        v["sections"]["knowledge"]["items"][0]["slug"] = json!(bad);
        invalid(&v);
    }
    let mut v = valid();
    v["sections"]["tasks"]["items"][0]["session_id"] = json!(MEMORY);
    assert!(
        decode(&v).is_ok(),
        "session need not appear in selected sessions"
    );
    v["sections"]["sessions"]["items"][0]["completed_tasks"] = json!(9_007_199_254_740_991_u64);
    v["sections"]["sessions"]["items"][0]["total_tasks"] = json!(9_007_199_254_740_991_u64);
    assert!(decode(&v).is_ok());
    for field in ["completed_tasks", "total_tasks"] {
        for bad in [
            json!(9_007_199_254_740_992_u64),
            json!(-1),
            json!(1.0),
            Value::Null,
        ] {
            let mut changed = v.clone();
            changed["sections"]["sessions"]["items"][0][field] = bad;
            invalid(&changed);
        }
    }
    let mut v = valid();
    v["sections"]["sessions"]["items"][0]["completed_tasks"] = json!(3);
    invalid(&v);
}

#[test]
fn public_actor_ulids_preserve_all_128_bits_in_each_section() {
    for identifier in [
        ulid::Ulid::nil(),
        ulid::Ulid::from(1u128),
        ulid::Ulid::from(u128::MAX),
    ] {
        for path in [
            "/sections/tasks/items/0/owner",
            "/sections/sessions/items/0/owner",
            "/sections/memories/items/0/updated_by",
        ] {
            let mut wire = valid();
            *wire.pointer_mut(path).unwrap() = json!(identifier.to_string());
            let data = decode(&wire).unwrap();
            assert_eq!(serde_json::to_value(data).unwrap(), wire);
        }
    }
}

#[test]
fn timestamps_keep_native_extremes_and_never_use_wall_clock_or_lexical_order() {
    for path in [
        "/generated_at",
        "/sections/tasks/items/0/lease_expires_at",
        "/sections/tasks/items/0/updated_at",
        "/sections/sessions/items/0/lease_expires_at",
        "/sections/sessions/items/0/updated_at",
        "/sections/memories/items/0/updated_at",
        "/sections/knowledge/items/0/updated_at",
    ] {
        for bad in [
            json!("+1"),
            json!("-0"),
            json!("01"),
            json!("1e6"),
            json!("1.0"),
            json!(""),
            json!(1000000),
            json!(1.5),
        ] {
            let mut v = valid();
            *v.pointer_mut(path).unwrap() = bad;
            invalid(&v);
        }
    }
    for path in [
        "/sections/tasks/items/0/updated_at",
        "/sections/sessions/items/0/updated_at",
        "/sections/memories/items/0/updated_at",
    ] {
        for bad in ["-1000000", "1", "18446744073709551616000000"] {
            let mut v = valid();
            *v.pointer_mut(path).unwrap() = json!(bad);
            invalid(&v);
        }
        let mut v = valid();
        *v.pointer_mut(path).unwrap() = json!("18446744073709551615000000");
        assert!(decode(&v).is_ok());
    }
    for time in ["-9223372036854775808", "9223372036854775807", "0"] {
        let mut v = valid();
        v["sections"]["knowledge"]["items"][0]["updated_at"] = json!(time);
        assert!(decode(&v).is_ok());
    }
    for time in ["-9223372036854775809", "9223372036854775808"] {
        let mut v = valid();
        v["sections"]["knowledge"]["items"][0]["updated_at"] = json!(time);
        invalid(&v);
    }
    for section in ["tasks", "sessions"] {
        for time in ["0", "1000000"] {
            let mut v = valid();
            v["sections"][section]["items"][0]["lease_expires_at"] = json!(time);
            invalid(&v);
        }
        let mut v = valid();
        v["sections"][section]["items"][0]["lease_expires_at"] =
            json!("18446744073709551615000000");
        assert!(decode(&v).is_ok());
    }
    let mut empty = valid();
    for section in ["tasks", "sessions", "memories", "knowledge"] {
        empty["sections"][section] = absent();
    }
    for generated in ["0", "18446744073709551615999999"] {
        empty["generated_at"] = json!(generated);
        assert!(decode(&empty).is_ok());
    }
    for generated in ["-1", "18446744073709551616000000"] {
        empty["generated_at"] = json!(generated);
        invalid(&empty);
    }
}

#[test]
fn numeric_sort_ties_duplicates_and_unknown_knowledge_times() {
    for section in ["tasks", "sessions", "memories"] {
        let mut v = valid();
        let mut second = v["sections"][section]["items"][0].clone();
        second["id"] = json!(ulid::Ulid::from(1_u128).to_string());
        v["sections"][section]["items"][0]["updated_at"] = json!("10000000");
        second["updated_at"] = json!("2000000");
        v["sections"][section]["items"]
            .as_array_mut()
            .unwrap()
            .push(second);
        v["sections"][section]["total"] = json!(2);
        assert!(decode(&v).is_ok());
        let mut reversed = v.clone();
        reversed["sections"][section]["items"]
            .as_array_mut()
            .unwrap()
            .reverse();
        invalid(&reversed);
        let mut duplicate = v.clone();
        duplicate["sections"][section]["items"][1]["id"] =
            duplicate["sections"][section]["items"][0]["id"].clone();
        invalid(&duplicate);
        v["sections"][section]["items"][0]["updated_at"] = json!("2000000");
        invalid(&v);
        v["sections"][section]["items"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(decode(&v).is_ok());
    }
    let mut v = valid();
    v["sections"]["knowledge"]["items"]
        .as_array_mut()
        .unwrap()
        .reverse();
    invalid(&v);
    let mut v = valid();
    v["sections"]["knowledge"]["items"][1]["slug"] = json!("known");
    invalid(&v);
    let mut v = valid();
    v["sections"]["knowledge"]["items"][1]["updated_at"] = json!("-1");
    assert!(decode(&v).is_ok());
    v["sections"]["knowledge"]["items"]
        .as_array_mut()
        .unwrap()
        .reverse();
    invalid(&v);
}

#[test]
fn complete_positional_objects_and_tagged_enum_maps_are_not_json_wire() {
    // Use declaration order, so these arrays would be valid derived structs.
    let wire = valid();
    let sections = &wire["sections"];
    let arrays = [
        (
            "",
            json!([wire["project_id"], wire["generated_at"], wire["sections"]]),
        ),
        (
            "/sections",
            json!([
                sections["tasks"],
                sections["sessions"],
                sections["memories"],
                sections["knowledge"]
            ]),
        ),
        (
            "/sections/tasks",
            json!(["available", sections["tasks"]["items"], 1, false, null]),
        ),
        (
            "/sections/sessions",
            json!(["available", sections["sessions"]["items"], 1, false, null]),
        ),
        (
            "/sections/memories",
            json!(["available", sections["memories"]["items"], 1, false, null]),
        ),
        (
            "/sections/knowledge",
            json!(["available", sections["knowledge"]["items"], 2, false, null]),
        ),
        (
            "/sections/tasks/items/0",
            json!([TASK, SESSION, "Task", ACTOR, "2000000", "1000000"]),
        ),
        (
            "/sections/sessions/items/0",
            json!([SESSION, "Session", ACTOR, "2000000", "1000000", 1, 2]),
        ),
        (
            "/sections/memories/items/0",
            json!([MEMORY, " memory ", ACTOR, "1000000"]),
        ),
        ("/sections/knowledge/items/0", json!(["known", "", "-1"])),
        (
            "/sections/knowledge/items/1",
            json!(["unknown", "Unknown time", null]),
        ),
    ];
    for (path, array) in arrays {
        let mut v = wire.clone();
        *v.pointer_mut(path).unwrap() = array;
        invalid(&v);
        let nested = json!({"op":"publish","snapshot":v});
        assert!(
            serde_json::from_slice::<PublishCommand>(&serde_json::to_vec(&nested).unwrap())
                .is_err()
        );
    }
    for section in ["tasks", "sessions", "memories", "knowledge"] {
        let mut v = wire.clone();
        v["sections"][section]["availability"] = json!({"available":null});
        invalid(&v);
        v["sections"][section] = json!({"availability":"failed","items":[],"total":null,"has_more":null,
            "error":{"forbidden":null}});
        invalid(&v);
    }
    assert!(
        serde_json::from_str::<broker_now_wire::NowSectionAvailability>(r#"{"available":null}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<broker_now_wire::NowSectionErrorCode>(r#"{"forbidden":null}"#)
            .is_err()
    );
}

fn forbidden() -> Value {
    json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":"forbidden"})
}

fn expected_mask(mut wire: Value, task: bool, memory: bool, knowledge: bool) -> Value {
    for (section, permitted) in [
        ("tasks", task),
        ("sessions", task),
        ("memories", memory),
        ("knowledge", knowledge),
    ] {
        if !permitted {
            wire["sections"][section] = forbidden();
        }
    }
    wire
}

#[test]
fn all_section_masks_preserve_literals_and_roundtrip_the_strict_codec() {
    for bits in 0..8 {
        let task = bits & 1 != 0;
        let memory = bits & 2 != 0;
        let knowledge = bits & 4 != 0;
        let wire = valid();
        let data = decode(&wire)
            .unwrap()
            .mask_sections(task, memory, knowledge);
        let actual = serde_json::to_value(&data).unwrap();
        let expected = expected_mask(wire, task, memory, knowledge);
        assert_eq!(actual, expected, "mask {bits}");
        assert_eq!(
            serde_json::to_value(decode(&actual).unwrap()).unwrap(),
            expected
        );
        let repeated = data.mask_sections(task, memory, knowledge);
        assert_eq!(serde_json::to_value(&repeated).unwrap(), expected);
        let enabled = repeated.mask_sections(true, true, true);
        assert_eq!(serde_json::to_value(&enabled).unwrap(), expected);
        let removed = enabled.mask_sections(false, false, false);
        assert_eq!(
            serde_json::to_value(&removed).unwrap(),
            expected_mask(valid(), false, false, false)
        );
    }
}

#[test]
fn mixed_section_states_are_preserved_or_replaced_with_forbidden() {
    for state in [
        absent(),
        available(json!([])),
        json!({"availability":"failed","items":[],"total":null,"has_more":null,"error":"counts_unavailable"}),
    ] {
        for bits in 0..8 {
            let task = bits & 1 != 0;
            let memory = bits & 2 != 0;
            let knowledge = bits & 4 != 0;
            let mut wire = valid();
            wire["sections"]["tasks"] = state.clone();
            wire["sections"]["memories"] = state.clone();
            wire["sections"]["knowledge"] = state.clone();
            let actual = serde_json::to_value(
                decode(&wire)
                    .unwrap()
                    .mask_sections(task, memory, knowledge),
            )
            .unwrap();
            assert_eq!(actual, expected_mask(wire, task, memory, knowledge));
            assert!(decode(&actual).is_ok());
        }
    }
}

#[test]
fn allowed_headers_vectors_and_row_strings_keep_their_allocations() {
    for bits in 0..8 {
        let task = bits & 1 != 0;
        let memory = bits & 2 != 0;
        let knowledge = bits & 4 != 0;
        let data = decode(&valid()).unwrap();
        let header = (data.project_id().as_ptr(), data.generated_at().as_ptr());
        let tasks = (
            data.sections().tasks().items().as_ptr(),
            data.sections().tasks().items()[0].title().as_ptr(),
        );
        let sessions = (
            data.sections().sessions().items().as_ptr(),
            data.sections().sessions().items()[0].title().as_ptr(),
        );
        let memories = (
            data.sections().memories().items().as_ptr(),
            data.sections().memories().items()[0].title().as_ptr(),
        );
        let knowledge_rows = (
            data.sections().knowledge().items().as_ptr(),
            data.sections().knowledge().items()[1].title().as_ptr(),
        );
        let masked = data.mask_sections(task, memory, knowledge);
        assert_eq!(
            header,
            (masked.project_id().as_ptr(), masked.generated_at().as_ptr())
        );
        if task {
            assert_eq!(
                tasks,
                (
                    masked.sections().tasks().items().as_ptr(),
                    masked.sections().tasks().items()[0].title().as_ptr()
                )
            );
            assert_eq!(
                sessions,
                (
                    masked.sections().sessions().items().as_ptr(),
                    masked.sections().sessions().items()[0].title().as_ptr()
                )
            );
        } else {
            assert!(masked.sections().tasks().items().is_empty());
            assert!(masked.sections().sessions().items().is_empty());
        }
        if memory {
            assert_eq!(
                memories,
                (
                    masked.sections().memories().items().as_ptr(),
                    masked.sections().memories().items()[0].title().as_ptr()
                )
            );
        } else {
            assert!(masked.sections().memories().items().is_empty());
        }
        if knowledge {
            assert_eq!(
                knowledge_rows,
                (
                    masked.sections().knowledge().items().as_ptr(),
                    masked.sections().knowledge().items()[1].title().as_ptr()
                )
            );
        } else {
            assert!(masked.sections().knowledge().items().is_empty());
        }
    }
}
