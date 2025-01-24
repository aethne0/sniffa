use chrono::Local;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use pnet::{datalink, packet::ethernet::EtherType};
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::Modifier;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Stylize,
    symbols::border,
    text::Line,
    widgets::{Block, List, ListItem, Widget},
    DefaultTerminal, Frame,
};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::yield_now;
use std::{collections::VecDeque, io, time::Duration};
use std::{
    sync::mpsc::{self, Receiver, Sender},
    thread,
};
use util::octets_to_ascii;
mod util;

fn main() -> io::Result<()> {
    let mut terminal = ratatui::init();
    let app_result = App::default().run(&mut terminal);
    ratatui::restore();
    app_result
}

#[derive(Debug)]
struct UIPacket {
    timestamp: chrono::DateTime<Local>,
    ethertype: EtherType,
    //source: MacAddr,
    //dest: MacAddr,
    packet: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct App {
    cursor_index: usize,
    writing: Arc<AtomicBool>,
    exiting: Arc<AtomicBool>,
    packet_buffer: VecDeque<Box<UIPacket>>,
    exit: bool,
}

impl App {
    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        self.cursor_index = 0;
        terminal.hide_cursor()?;
        self.writing.store(true, Ordering::Relaxed);
        self.exiting.store(false, Ordering::Relaxed);

        let interface_vec = datalink::interfaces();
        let mut interface_threads = vec![];

        let (packet_tx, packet_rx): (Sender<UIPacket>, Receiver<UIPacket>) = mpsc::channel();
        for interface in interface_vec {
            let cloned_packet_tx = packet_tx.clone();
            let cloned_writing = Arc::clone(&self.writing);
            let cloned_exiting = Arc::clone(&self.exiting);
            let handle = thread::spawn(move || {
                capture_packets(interface, cloned_packet_tx, cloned_writing, cloned_exiting);
            });
            interface_threads.push(handle);
        }
        // Wait for all threads to complete

        fn capture_packets(
            interface: datalink::NetworkInterface,
            c_tx: Sender<UIPacket>,
            writing: Arc<AtomicBool>,
            exiting: Arc<AtomicBool>,
        ) {
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unhandled channel type: {}", &interface),
                Err(e) => panic!(
                    "An error occurred when creating the datalink channel: {}",
                    e
                ),
            };

            loop {
                if exiting.load(Ordering::Relaxed) {
                    return;
                }
                match rx.next() {
                    Ok(packet) => {
                        if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                            if writing.load(Ordering::Relaxed) {
                                c_tx.send(UIPacket {
                                    timestamp: chrono::offset::Local::now(),
                                    ethertype: ethernet_packet.get_ethertype(),
                                    //source: ethernet_packet.get_source(),
                                    //dest: ethernet_packet.get_destination(),
                                    packet: ethernet_packet.packet().into(),
                                })
                                .unwrap();
                            }
                        }
                    }
                    Err(e) => {
                        panic!("An error occurred while reading: {}", e);
                    }
                }
                yield_now();
            }
        }

        while !self.exit {
            if self.writing.load(Ordering::Relaxed) {
                match packet_rx.try_recv() {
                    Ok(v) => {
                        if self.packet_buffer.len() > 100 {
                            self.packet_buffer.pop_front();
                        }
                        self.packet_buffer.push_back(Box::new(v));
                    }
                    _ => (),
                }
            } else {
                while let Ok(_) = packet_rx.try_recv() {}
            }
            self.handle_events()?;
            if self.cursor_index > self.packet_buffer.len() {
                self.cursor_index = self.packet_buffer.len();
            }
            terminal.draw(|frame| self.draw(frame))?;
        }

        for handle in interface_threads {
            handle.join().unwrap();
        }

        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        let writing = self.writing.load(Ordering::Relaxed);

        let instructions = Line::from(vec![
            " Capture".into(),
            " <r> ".blue().bold(),
            " Pause".into(),
            " <t> ".blue().bold(),
            " Clear".into(),
            " <c> ".blue().bold(),
            " Quit".into(),
            " <q> ".blue().bold(),
        ]);

        let counter_text = if !self.exiting.load(Ordering::Relaxed) {
            Line::from(vec![
                " Sniffa: ".into(),
                (if self.writing.load(Ordering::Relaxed) {
                    "Capturing...".green()
                } else {
                    "Capturing paused.".red()
                }),
                " ".into(),
            ])
        } else {
            Line::from(" Closing... ".yellow())
        };

        //.title_bottom(instructions.centered())

        //frame.render_widget(self, frame.area());
        let chunks = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(frame.area());

        let block = Block::bordered()
            .title_top(counter_text.centered())
            .title_bottom(instructions.centered())
            .border_set(border::THICK);

        let mut packet_lines: Vec<ListItem> = Vec::new();
        let max_lines = if writing {
            block.inner(frame.area()).height as usize
        } else {
            chunks[0].inner(Margin::new(1, 1)).height as usize // how do i get this properly?
        };
        for (index, packet) in self
            .packet_buffer
            .iter()
            .enumerate()
            .rev()
            .take(max_lines)
            .rev()
        {
            let ethertype_str = format!("({})", packet.ethertype);
            let time_str = format!("{}", packet.timestamp.format("%H:%M:%S%.3f"));
            packet_lines.push(
                ListItem::new(Line::from(vec![
                    time_str.gray().into(),
                    ":  ".into(),
                    format!(" {:>9}", ethertype_str).yellow(),
                    " | ".into(),
                    format!("len:{:>5}", packet.packet.len()).magenta(),
                    " | ".into(),
                    if packet.ethertype == EtherTypes::Ipv4 {
                        format!(
                            "{:>15}",
                            packet.packet[26..=29]
                                .iter()
                                .map(|octet| { format!("{}", octet) })
                                .collect::<Vec<_>>()
                                .join(".")
                        )
                        .black()
                        .on_light_cyan()
                        .into()
                    } else {
                        "".into()
                    },
                    if packet.ethertype == EtherTypes::Ipv4 {
                        " -> ".into()
                    } else {
                        "".into()
                    },
                    if packet.ethertype == EtherTypes::Ipv4 {
                        format!(
                            "{:>15}",
                            packet.packet[30..=33]
                                .iter()
                                .map(|octet| { format!("{}", octet) })
                                .collect::<Vec<_>>()
                                .join(".")
                        )
                        .black()
                        .on_light_green()
                        .into()
                    } else {
                        "".into()
                    },
                ]))
                .add_modifier(if self.cursor_index == index && !writing {
                    Modifier::REVERSED
                } else {
                    Modifier::DIM
                }),
            );
        }

        let list = List::new(packet_lines).block(block);

        if writing || self.packet_buffer.len() == 0 {
            frame.render_widget(
                list,
                frame.area().inner(Margin {
                    horizontal: 1,
                    vertical: 1,
                }),
            );
        } else {
            let mut octet_lines: Vec<ListItem> = Vec::new();
            let max_octet_lines = chunks[1].height as usize;

            match self.packet_buffer.get(self.cursor_index) {
                Some(packet) => {
                    let chunks = packet.packet.chunks(16);

                    for (chunk_index, chunk) in chunks.take(max_octet_lines).enumerate() {
                        octet_lines.push(ListItem::new(Line::from(vec![
                            format!(
                                "{:<56}",
                                chunk
                                    .iter()
                                    .enumerate()
                                    .map(|(line_index, octet)| {
                                        if line_index == 0 {
                                            format!("{:04X}: {:02X}", chunk_index * 16, octet)
                                        } else if line_index % 4 == 0 {
                                            format!(" {:02X}", octet)
                                        } else {
                                            format!("{:02X}", octet)
                                        }
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            )
                            .into(),
                            " | ".into(),
                            octets_to_ascii(chunk).into(),
                        ])))
                    }
                }
                _ => (),
            }

            let octets = List::new(octet_lines);

            frame.render_widget(
                list,
                chunks[0].inner(Margin {
                    horizontal: 1,
                    vertical: 0,
                }),
            );
            frame.render_widget(octets, chunks[1]);
        }
    }

    /// updates the application's state based on user input
    fn handle_events(&mut self) -> io::Result<()> {
        if event::poll(Duration::from_millis(0))? {
            match event::read()? {
                Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                    self.handle_key_event(key_event)
                }
                _ => {}
            };
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => {
                self.exiting.store(true, Ordering::Relaxed);
                self.exit()
            }
            KeyCode::Char('r') => {
                self.writing.store(true, Ordering::Relaxed);
            }
            KeyCode::Char('t') => {
                self.writing.store(false, Ordering::Relaxed);
                self.cursor_index = self.packet_buffer.len().saturating_sub(1);
            }
            KeyCode::Char('c') => {
                self.packet_buffer.clear();
            }
            KeyCode::Down => self.decrement_counter(),
            KeyCode::Up => self.increment_counter(),
            KeyCode::Left => self.cursor_index = 0,
            KeyCode::Right => self.cursor_index = self.packet_buffer.len().saturating_sub(1),
            _ => {}
        }
    }

    fn exit(&mut self) {
        self.exit = true;
    }

    fn increment_counter(&mut self) {
        self.cursor_index = self.cursor_index.saturating_sub(1);
    }

    fn decrement_counter(&mut self) {
        if self.cursor_index < self.packet_buffer.len() {
            self.cursor_index += 1;
        }
    }
}

impl Widget for &App {
    fn render(self, _area: Rect, _buf: &mut Buffer) {}
}
