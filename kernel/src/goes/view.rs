#![cfg(target_os = "none")]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::replay::{EdgeInfo, Index, ObjectInfo};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewOrder {
    SeqAsc,
    SeqDesc,
}

#[derive(Clone, Debug)]
pub enum ViewFilter {
    ObjType(u32),
    Owner(String),
    OutEdges(u64),
    InEdges(u64),
}

#[derive(Clone, Debug)]
pub struct ViewObject {
    pub sources: Vec<String>,
    pub filters: Vec<ViewFilter>,
    pub order: ViewOrder,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum ViewRow {
    Object(ObjectInfo),
    Edge(EdgeInfo),
}

impl ViewObject {
    pub fn roots(source_ws: &str) -> Self {
        Self {
            sources: alloc::vec![String::from(source_ws)],
            filters: Vec::new(),
            order: ViewOrder::SeqAsc,
            limit: None,
        }
    }

    pub fn roots_union(sources: &[String]) -> Self {
        Self {
            sources: sources.to_vec(),
            filters: Vec::new(),
            order: ViewOrder::SeqAsc,
            limit: None,
        }
    }

    pub fn with_filter(mut self, f: ViewFilter) -> Self {
        self.filters.push(f);
        self
    }

    pub fn with_order(mut self, order: ViewOrder) -> Self {
        self.order = order;
        self
    }

    pub fn with_limit(mut self, limit: Option<usize>) -> Self {
        self.limit = limit;
        self
    }
}

pub fn run_view(view: &ViewObject, idx: &Index) -> Vec<ViewRow> {
    let mut out = Vec::new();

    let mut out_edges = None::<u64>;
    let mut in_edges = None::<u64>;
    let mut obj_type = None::<u32>;
    let mut owner = None::<String>;

    for f in view.filters.iter() {
        match f {
            ViewFilter::OutEdges(id) => out_edges = Some(*id),
            ViewFilter::InEdges(id) => in_edges = Some(*id),
            ViewFilter::ObjType(t) => obj_type = Some(*t),
            ViewFilter::Owner(o) => owner = Some(o.clone()),
        }
    }

    if let Some(id) = out_edges {
        for e in idx.edges.iter().filter(|e| e.from == id && !e.removed) {
            out.push(ViewRow::Edge(e.clone()));
        }
        sort_edges(&mut out, view.order);
        apply_limit(&mut out, view.limit);
        return out;
    }

    if let Some(id) = in_edges {
        for e in idx.edges.iter().filter(|e| e.to == id && !e.removed) {
            out.push(ViewRow::Edge(e.clone()));
        }
        sort_edges(&mut out, view.order);
        apply_limit(&mut out, view.limit);
        return out;
    }

    for o in idx.objects.values() {
        if !view.sources.iter().any(|ws| ws == &o.workspace) {
            continue;
        }
        if let Some(t) = obj_type {
            if o.obj_type != t {
                continue;
            }
        }
        if let Some(ref who) = owner {
            let mut target = String::from("User:");
            target.push_str(who);
            if !view.sources.iter().any(|ws| ws == &target) {
                continue;
            }
        }
        out.push(ViewRow::Object(o.clone()));
    }

    sort_objects(&mut out, view.order);
    apply_limit(&mut out, view.limit);
    out
}

fn apply_limit(rows: &mut Vec<ViewRow>, limit: Option<usize>) {
    let Some(limit) = limit else { return };
    if rows.len() > limit {
        rows.truncate(limit);
    }
}

fn sort_objects(rows: &mut Vec<ViewRow>, order: ViewOrder) {
    rows.sort_by(|a, b| match (a, b) {
        (ViewRow::Object(oa), ViewRow::Object(ob)) => {
            let key_a = (oa.created_seq, oa.id);
            let key_b = (ob.created_seq, ob.id);
            match order {
                ViewOrder::SeqAsc => key_a.cmp(&key_b),
                ViewOrder::SeqDesc => key_b.cmp(&key_a),
            }
        }
        _ => core::cmp::Ordering::Equal,
    });
}

fn sort_edges(rows: &mut Vec<ViewRow>, order: ViewOrder) {
    rows.sort_by(|a, b| match (a, b) {
        (ViewRow::Edge(ea), ViewRow::Edge(eb)) => match order {
            ViewOrder::SeqAsc => ea.seq.cmp(&eb.seq),
            ViewOrder::SeqDesc => eb.seq.cmp(&ea.seq),
        },
        _ => core::cmp::Ordering::Equal,
    });
}
