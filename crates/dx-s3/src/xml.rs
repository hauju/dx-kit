//! The three XML shapes this crate reads (`Error`, `ListBucketResult`,
//! `DeleteResult`) and the one it writes (`Delete`).

use roxmltree::{Document, Node};

use crate::error::{Error, Result};
use crate::types::ListedObject;

fn child_text<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
        .and_then(|c| c.text())
}

fn elements<'a, 'i>(node: Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

/// `(<Code>, <Message>)` from an S3 error body, if it is one.
pub(crate) fn parse_error(body: &str) -> (Option<String>, Option<String>) {
    let Ok(doc) = Document::parse(body) else {
        return (None, None);
    };
    let root = doc.root_element();
    if root.tag_name().name() != "Error" {
        return (None, None);
    }
    (
        child_text(root, "Code").map(str::to_string),
        child_text(root, "Message").map(str::to_string),
    )
}

pub(crate) struct ListPage {
    pub objects: Vec<ListedObject>,
    /// The continuation token for the next page, when `IsTruncated` was true.
    pub next: Option<String>,
}

/// One page of a `ListObjectsV2` response. Keys are the full stored keys;
/// the caller strips the path prefix.
pub(crate) fn parse_list(body: &str) -> Result<ListPage> {
    let doc = Document::parse(body).map_err(|e| Error::Xml(e.to_string()))?;
    let root = doc.root_element();
    if root.tag_name().name() != "ListBucketResult" {
        return Err(Error::Xml(format!(
            "expected ListBucketResult, got {}",
            root.tag_name().name()
        )));
    }
    let objects = elements(root, "Contents")
        .map(|c| {
            let key =
                child_text(c, "Key").ok_or_else(|| Error::Xml("Contents without Key".into()))?;
            Ok(ListedObject {
                key: key.to_string(),
                size: child_text(c, "Size")
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0),
                etag: child_text(c, "ETag").map(|e| e.trim_matches('"').to_string()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let truncated = child_text(root, "IsTruncated").is_some_and(|t| t.trim() == "true");
    let next = child_text(root, "NextContinuationToken")
        .filter(|_| truncated)
        .map(str::to_string);
    Ok(ListPage { objects, next })
}

/// Body for a quiet `DeleteObjects` request.
pub(crate) fn delete_request(keys: &[String]) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>true</Quiet>"#);
    for key in keys {
        xml.push_str("<Object><Key>");
        for ch in key.chars() {
            match ch {
                '&' => xml.push_str("&amp;"),
                '<' => xml.push_str("&lt;"),
                '>' => xml.push_str("&gt;"),
                '"' => xml.push_str("&quot;"),
                '\'' => xml.push_str("&apos;"),
                c => xml.push(c),
            }
        }
        xml.push_str("</Key></Object>");
    }
    xml.push_str("</Delete>");
    xml
}

/// `(key, code)` for every `<Error>` in a `DeleteResult`. In quiet mode that
/// is the whole body.
pub(crate) fn delete_errors(body: &str) -> Vec<(String, String)> {
    let Ok(doc) = Document::parse(body) else {
        return Vec::new();
    };
    elements(doc.root_element(), "Error")
        .map(|e| {
            (
                child_text(e, "Key").unwrap_or_default().to_string(),
                child_text(e, "Code").unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>a.png</Key></Error>"#;
        assert_eq!(
            parse_error(body),
            (
                Some("NoSuchKey".into()),
                Some("The specified key does not exist.".into())
            )
        );
        assert_eq!(parse_error("<CopyObjectResult/>"), (None, None));
        assert_eq!(parse_error("not xml"), (None, None));
        assert_eq!(parse_error(""), (None, None));
    }

    #[test]
    fn list_page_with_namespace_and_continuation() {
        let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>media</Name><Prefix>uploads/</Prefix><KeyCount>2</KeyCount><MaxKeys>2</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
  <Contents><Key>uploads/a &amp; b.png</Key><LastModified>2026-09-01T10:00:00.000Z</LastModified><ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag><Size>12</Size><StorageClass>STANDARD</StorageClass></Contents>
  <Contents><Key>uploads/c.png</Key><ETag>"abc"</ETag><Size>34</Size></Contents>
</ListBucketResult>"#;
        let page = parse_list(body).unwrap();
        assert_eq!(
            page.next.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
        );
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "uploads/a & b.png");
        assert_eq!(page.objects[0].size, 12);
        assert_eq!(
            page.objects[0].etag.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(page.objects[1].key, "uploads/c.png");
    }

    #[test]
    fn last_page_has_no_continuation() {
        let body = r#"<ListBucketResult><IsTruncated>false</IsTruncated><KeyCount>0</KeyCount></ListBucketResult>"#;
        let page = parse_list(body).unwrap();
        assert!(page.objects.is_empty());
        assert!(page.next.is_none());
        assert!(matches!(parse_list("<Error/>"), Err(Error::Xml(_))));
        assert!(matches!(parse_list("<<"), Err(Error::Xml(_))));
    }

    #[test]
    fn delete_request_escapes_keys() {
        let xml = delete_request(&["a&b.png".into(), "c<d>.png".into()]);
        assert_eq!(
            xml,
            r#"<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>true</Quiet><Object><Key>a&amp;b.png</Key></Object><Object><Key>c&lt;d&gt;.png</Key></Object></Delete>"#
        );
    }

    #[test]
    fn delete_result_errors() {
        let body = r#"<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Error><Key>locked.png</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>
</DeleteResult>"#;
        assert_eq!(
            delete_errors(body),
            vec![("locked.png".to_string(), "AccessDenied".to_string())]
        );
        assert!(delete_errors("<DeleteResult/>").is_empty());
        assert!(delete_errors("").is_empty());
    }
}
