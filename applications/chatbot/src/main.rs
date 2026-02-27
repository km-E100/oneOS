#![no_std]
#![no_main]

use core::panic::PanicInfo;
use oneos_app::{console_read, console_write_line, console_write_str, watchdog_feed, AppApiV1};

/// Panic handler: loop forever.  oneOS apps abort on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// The maximum number of tokens we consider when parsing a user message.
const MAX_TOKENS: usize = 16;

/// Stopwords are common English words that carry little semantic meaning.
/// We exclude these when computing similarity between the user's query
/// and the knowledge base questions.  All words must be in lowercase.
const STOPWORDS: &[&str] = &[
    "the", "a", "an", "is", "are", "am", "i", "you", "your", "yours",
    "to", "of", "and", "or", "in", "on", "for", "with", "about", "me",
    "my", "it", "that", "this", "these", "those", "do", "did", "does",
    "can", "could", "would", "should", "have", "has", "had", "be", "been",
    "when", "where", "why", "how", "what", "who", "whom", "which", "at",
    "by", "as", "if", "but", "not", "no", "yes", "hello", "hi", "hey"
];

/// An entry in the knowledge base.  Each entry consists of a question
/// represented as lowercase ASCII bytes and its corresponding answer as
/// an English string.  The question should avoid punctuation and be
/// composed of plain words so that matching tokens works correctly.
struct KnowledgeItem {
    question: &'static [u8],
    answer: &'static str,
}

/// Knowledge base with a few general question‑answer pairs.  You can
/// extend this list to teach the bot new facts.  All questions must
/// be lowercase ASCII without punctuation.  Answers may contain
/// punctuation and proper case.
const KNOWLEDGE: &[KnowledgeItem] = &[
    KnowledgeItem { question: b"what is your name", answer: "I'm FriendlyBot, your chat companion." },
    KnowledgeItem { question: b"how are you", answer: "I'm just a bunch of code, but I'm here to chat with you!" },
    KnowledgeItem { question: b"tell me a joke", answer: "Why don't scientists trust atoms? Because they make up everything!" },
    KnowledgeItem { question: b"how does this system work", answer: "I use simple pattern matching and a small knowledge base to answer your questions." },
    KnowledgeItem { question: b"what time is it", answer: "I don't have access to real time, but I hope you're having a great day!" },
    KnowledgeItem { question: b"what is rust language", answer: "Rust is a systems programming language focused on safety and performance." },
    KnowledgeItem { question: b"tell me about openai", answer: "OpenAI is an artificial intelligence research and deployment company." },
    KnowledgeItem { question: b"give me advice", answer: "Sometimes the best advice is to trust yourself and keep going." },
    KnowledgeItem { question: b"who created you", answer: "I was created by a developer using oneOS and Rust." },
    KnowledgeItem { question: b"who is the president of united states", answer: "I'm not connected to the internet, so please check a reliable source for current information." },
];

/// State remembered across user inputs.  We store the user's name and a
/// limited set of things they like.  We also remember the index of the
/// last knowledge entry used to allow simple follow‑up questions.
struct State {
    // name buffer and length
    name: [u8; 24],
    name_len: usize,
    // topics the user likes
    topics: [[u8; 20]; 5],
    topics_count: usize,
    // index of the last knowledge entry used (if any)
    last_kb_index: Option<usize>,
}

impl State {
    fn new() -> Self {
        State {
            name: [0; 24],
            name_len: 0,
            topics: [[0; 20]; 5],
            topics_count: 0,
            last_kb_index: None,
        }
    }
}

/// Normalize an input string by converting ASCII letters to lowercase,
/// converting punctuation to spaces, and preserving digits and spaces.
/// Returns a slice into `out` trimmed of leading and trailing spaces.
fn normalize<'a>(input: &[u8], out: &'a mut [u8]) -> &'a [u8] {
    let mut n = 0usize;
    for &b in input {
        let c = match b {
            b'A'..=b'Z' => b + 32,              // uppercase to lowercase
            b'a'..=b'z' | b'0'..=b'9' | b' ' => b, // keep letters, digits, spaces
            _ => b' ',                           // convert punctuation to space
        };
        if n < out.len() {
            out[n] = c;
            n += 1;
        }
    }
    trim(&out[..n])
}

/// Remove leading and trailing spaces from a byte slice.
fn trim(mut s: &[u8]) -> &[u8] {
    while !s.is_empty() && s[0] == b' ' {
        s = &s[1..];
    }
    while !s.is_empty() && s[s.len() - 1] == b' ' {
        s = &s[..s.len() - 1];
    }
    s
}

/// Determine whether a token is a stopword.  Comparison is
/// case‑sensitive on lowercase ASCII.  Accepts a slice representing a
/// single word without spaces.
fn is_stopword(token: &[u8]) -> bool {
    // Compare token to each stopword in STOPWORDS.  We avoid
    // allocating strings by converting token to &str using
    // from_utf8_unchecked since we know our inputs are ASCII.  If
    // conversion fails due to invalid UTF‑8, we treat it as not a
    // stopword.
    if let Ok(s) = core::str::from_utf8(token) {
        for &word in STOPWORDS {
            if s == word {
                return true;
            }
        }
    }
    false
}

/// Tokenize a normalized string into up to MAX_TOKENS non‑stopword
/// tokens.  Returns the number of tokens found and fills the
/// `tokens` array with slices into `s`.  The slices refer to
/// segments of `s` and therefore must not outlive `s`.
fn tokenize<'a>(s: &'a [u8], tokens: &mut [&'a [u8]; MAX_TOKENS]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < s.len() {
        // skip spaces
        if s[i] == b' ' {
            i += 1;
            continue;
        }
        // start of a word
        let start = i;
        while i < s.len() && s[i] != b' ' {
            i += 1;
        }
        let end = i;
        let word = &s[start..end];
        if !is_stopword(word) {
            if count < MAX_TOKENS {
                tokens[count] = word;
                count += 1;
            }
        }
    }
    count
}

/// Compute a simple overlap score between the user's token list and a
/// knowledge question.  Each token found in the question contributes
/// 1 to the score.  Tokens that are prefixes of longer words in the
/// question are considered matches.  Returns the score.
fn score_question(question: &[u8], tokens: &[&[u8]]) -> u32 {
    let mut score = 0u32;
    for &token in tokens.iter() {
        if token.is_empty() { continue; }
        // naive substring search
        let tlen = token.len();
        if question.len() < tlen { continue; }
        let mut j = 0usize;
        while j <= question.len() - tlen {
            if &question[j..j + tlen] == token {
                score += 1;
                break;
            }
            j += 1;
        }
    }
    score
}

/// Determine if the user message is a follow‑up like "tell me more".
/// For now we treat any message containing "it" or "that" as a
/// potential follow up.  This is very simple and can be refined.
fn is_follow_up(tokens: &[&[u8]], token_count: usize) -> bool {
    for i in 0..token_count {
        if let Ok(word) = core::str::from_utf8(tokens[i]) {
            if word == "it" || word == "that" || word == "more" {
                return true;
            }
        }
    }
    false
}

/// Write a slice of bytes to the console one byte at a time via
/// console_write_str.  Assumes UTF‑8 and that `api` is valid.
unsafe fn write_bytes(api: *const AppApiV1, bytes: &[u8]) {
    for &ch in bytes {
        let s = core::str::from_utf8_unchecked(core::slice::from_ref(&ch));
        console_write_str(api, s);
    }
}

/// Check if a given topic already exists in the topics list.
fn topic_exists(topics: &[[u8; 20]; 5], count: usize, topic: &[u8]) -> bool {
    for i in 0..count {
        let t = &topics[i];
        let mut tlen = 0usize;
        while tlen < t.len() && t[tlen] != 0 { tlen += 1; }
        if tlen == topic.len() && &t[..tlen] == topic {
            return true;
        }
    }
    false
}

/// Copy characters from `src` into `dst` (skipping spaces) until either
/// `dst` is full or `src` is exhausted.  Returns the number of bytes
/// written.
fn copy(dst: &mut [u8], src: &[u8]) -> usize {
    let mut i = 0usize;
    for &b in src {
        if b == b' ' { continue; }
        if i < dst.len() {
            dst[i] = b;
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Entry point for the advanced chatbot.  Implements a friendly
/// conversational agent using a small knowledge base and simple
/// pattern matching.  The bot remembers your name and things you
/// like, answers questions from its knowledge base, and gracefully
/// handles unknown inputs with reflective prompts.  It feeds the
/// watchdog on each loop to avoid timeouts.
#[no_mangle]
pub extern "C" fn oneos_app_main(api: *const AppApiV1) -> i32 {
    // Print introductory message
    unsafe {
        console_write_line(api, "FriendlyBot on oneOS - chat with me! ✅");
        console_write_line(api, "Type 'help' for assistance and 'bye' to exit.");
    }

    // Initialize state
    let mut state = State::new();
    // Buffers for input and normalized input
    let mut buf: [u8; 128] = [0; 128];
    let mut norm: [u8; 128] = [0; 128];

    loop {
        // Feed watchdog each iteration
        unsafe { watchdog_feed(api) };
        // Prompt
        unsafe { console_write_str(api, "\n> "); }
        // Read a line from console.  Non‑blocking reads return <= 0
        let n = unsafe { console_read(api, &mut buf) };
        if n <= 0 {
            // Nothing read, continue
            continue;
        }
        // Normalize input
        let line = normalize(&buf[..n as usize], &mut norm);
        if line.is_empty() {
            continue;
        }

        // Check for exit commands
        if eq(line, b"bye") || eq(line, b"exit") || eq(line, b"quit") {
            unsafe { console_write_line(api, "Goodbye! Thanks for chatting."); }
            break;
        }

        // Tokenize the normalized input, ignoring stopwords
        let mut token_buf: [&[u8]; MAX_TOKENS] = [b""; MAX_TOKENS];
        let token_count = tokenize(line, &mut token_buf);

        // Check for help command
        if token_count > 0 {
            if let Ok(cmd) = core::str::from_utf8(token_buf[0]) {
                if cmd == "help" {
                    unsafe {
                        console_write_line(api, "Commands:");
                        console_write_line(api, "  hello/hi     – greet me");
                        console_write_line(api, "  my name is <name> – introduce yourself");
                        console_write_line(api, "  what is my name – ask me to recall your name");
                        console_write_line(api, "  i like <topic> – tell me your interests");
                        console_write_line(api, "  what do i like – recall your interests");
                        console_write_line(api, "  <question>    – ask me anything I might know");
                        console_write_line(api, "  bye/exit/quit – exit the chat");
                    }
                    // Do not process further
                    continue;
                }
            }
        }

        // Greetings: respond friendly and include user's name if known
        if contains_word(line, b"hello") || contains_word(line, b"hi") || contains_word(line, b"hey") {
            unsafe {
                if state.name_len > 0 {
                    console_write_str(api, "Hey, ");
                    write_bytes(api, &state.name[..state.name_len]);
                    console_write_line(api, "! Nice to see you.");
                } else {
                    console_write_line(api, "Hey there! I'm FriendlyBot.");
                }
            }
            state.last_kb_index = None;
            continue;
        }

        // Remember name: "my name is <name>"
        if let Some(rest) = strip_prefix(line, b"my name is") {
            let rest = trim(rest);
            if !rest.is_empty() {
                state.name_len = copy(&mut state.name, rest);
                unsafe {
                    console_write_str(api, "Nice to meet you, ");
                    write_bytes(api, &state.name[..state.name_len]);
                    console_write_line(api, "!");
                }
            } else {
                unsafe { console_write_line(api, "Please tell me your name after 'my name is'."); }
            }
            state.last_kb_index = None;
            continue;
        }

        // Recall name
        if contains_subslice(line, b"what is my name") {
            unsafe {
                if state.name_len == 0 {
                    console_write_line(api, "I don't know your name yet. Introduce yourself with 'my name is …'.");
                } else {
                    console_write_str(api, "Your name is ");
                    write_bytes(api, &state.name[..state.name_len]);
                    console_write_line(api, ".");
                }
            }
            state.last_kb_index = None;
            continue;
        }

        // Interests: "i like <topic>" or "i love <topic>"
        if let Some(rest) = strip_prefix(line, b"i like") {
            handle_like(api, trim(rest), &mut state.topics, &mut state.topics_count);
            state.last_kb_index = None;
            continue;
        }
        if let Some(rest) = strip_prefix(line, b"i love") {
            handle_like(api, trim(rest), &mut state.topics, &mut state.topics_count);
            state.last_kb_index = None;
            continue;
        }

        // Recall interests: "what do i like"
        if contains_subslice(line, b"what do i like") {
            handle_what_do_i_like(api, &state.topics, state.topics_count);
            state.last_kb_index = None;
            continue;
        }

        // Simple follow‑up: if user says "it", "that" or "more" and we have a last knowledge index
        let follow = is_follow_up(&token_buf, token_count);
        if follow {
            if let Some(idx) = state.last_kb_index {
                // repeat answer or prompt for more
                unsafe {
                    console_write_line(api, KNOWLEDGE[idx].answer);
                }
                // keep last_kb_index unchanged
                continue;
            }
        }

        // Lookup in knowledge base
        let mut best_idx: Option<usize> = None;
        let mut best_score: u32 = 0;
        // compute scores for each knowledge item
        for (i, item) in KNOWLEDGE.iter().enumerate() {
            let score = score_question(item.question, &token_buf[..token_count]);
            if score > best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }

        if best_score > 0 {
            let idx = best_idx.unwrap();
            state.last_kb_index = Some(idx);
            unsafe {
                // Make the answer sound friendly and personal
                if state.name_len > 0 {
                    // v1: keep output minimal; avoid heap formatting in no_std.
                }
                console_write_line(api, KNOWLEDGE[idx].answer);
            }
            continue;
        }

        // If we reach here, no knowledge entry matched.  Provide
        // reflective fallback based on a simple checksum of the input.
        reflective_fallback(api, line);
        state.last_kb_index = None;
    }
    0
}

/// Check if two ASCII slices are equal.
fn eq(s: &[u8], w: &[u8]) -> bool {
    s == w
}

/// Determine if the haystack contains the needle as a substring.
fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if hay.len() < needle.len() { return false; }
    let mut i = 0usize;
    while i <= hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

/// Determine if the normalized line contains a specific lowercase
/// word as a standalone token.  This prevents matching substrings
/// inside larger words.
fn contains_word(line: &[u8], word: &[u8]) -> bool {
    if word.is_empty() || line.len() < word.len() { return false; }
    let mut i = 0usize;
    while i <= line.len() - word.len() {
        // ensure match at word boundary: start of string or preceding space
        if (i == 0 || line[i - 1] == b' ') && &line[i..i + word.len()] == word {
            // ensure following boundary: end of string or space
            let end = i + word.len();
            if end == line.len() || line[end] == b' ' {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Remove a prefix from a slice if it begins with that prefix followed
/// by a space or end of slice.  Returns the remainder of the slice
/// after the prefix or None if the prefix does not match.
fn strip_prefix<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if s.len() >= prefix.len() {
        if &s[..prefix.len()] == prefix {
            // prefix must be followed by space or end
            if s.len() == prefix.len() {
                return Some(&s[prefix.len()..]);
            }
            if s[prefix.len()] == b' ' {
                return Some(&s[prefix.len()..]);
            }
        }
    }
    None
}

/// Handle "i like <topic>" or "i love <topic>" statements.  Stores
/// the topic in the topics list if it is new and prints an
/// acknowledgement.  The topic is taken as the first word after the
/// prefix.  Only ASCII letters and digits are preserved.
fn handle_like(api: *const AppApiV1, rest: &[u8], topics: &mut [[u8; 20]; 5], count: &mut usize) {
    // Extract the first non‑space sequence
    let mut topic_buf = [0u8; 20];
    let mut tlen = 0usize;
    for &b in rest {
        if b == b' ' { break; }
        if tlen < topic_buf.len() {
            topic_buf[tlen] = b;
            tlen += 1;
        }
    }
    if tlen == 0 {
        unsafe { console_write_line(api, "Tell me something you like after 'i like'."); }
        return;
    }
    let topic = &topic_buf[..tlen];
    if topic_exists(topics, *count, topic) {
        unsafe {
            console_write_str(api, "You already told me you like ");
            write_bytes(api, topic);
            console_write_line(api, ".");
        }
    } else {
        if *count < topics.len() {
            // store new topic
            for j in 0..tlen { topics[*count][j] = topic[j]; }
            for j in tlen..topics[*count].len() { topics[*count][j] = 0; }
            *count += 1;
            unsafe {
                console_write_str(api, "Cool, I'll remember that you like ");
                write_bytes(api, topic);
                console_write_line(api, ".");
            }
        } else {
            unsafe {
                console_write_str(api, "I remember that you like ");
                write_bytes(api, topic);
                console_write_line(api, ", but my list is full.");
            }
        }
    }
}

/// Handle "what do i like" queries.  Prints the list of topics
/// stored.  If none are stored, prompts the user to tell the bot.
fn handle_what_do_i_like(api: *const AppApiV1, topics: &[[u8; 20]; 5], count: usize) {
    if count == 0 {
        unsafe {
            console_write_line(api, "I don't know what you like yet. Tell me something you like.");
        }
        return;
    }
    unsafe { console_write_str(api, "You mentioned that you like "); }
    for i in 0..count {
        let t = &topics[i];
        let mut tlen = 0usize;
        while tlen < t.len() && t[tlen] != 0 { tlen += 1; }
        if tlen > 0 {
            unsafe { write_bytes(api, &t[..tlen]); }
            if i + 2 == count {
                unsafe { console_write_str(api, " and "); }
            } else if i + 1 < count {
                unsafe { console_write_str(api, ", "); }
            }
        }
    }
    unsafe { console_write_line(api, "."); }
}

/// Provide a reflective fallback response when no rule matches.  Uses a
/// simple checksum of the input to select a response variation.
fn reflective_fallback(api: *const AppApiV1, line: &[u8]) {
    let mut sum: u32 = 0;
    for &b in line {
        sum = sum.wrapping_add(b as u32);
    }
    let variant = sum % 4;
    unsafe {
        match variant {
            0 => console_write_line(api, "That's interesting! Tell me more."),
            1 => console_write_line(api, "I see. How does that make you feel?"),
            2 => console_write_line(api, "Why do you think that is?"),
            _ => console_write_line(api, "Let's talk more about it. What else can you share?"),
        };
    }
}
