#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::{egui, App};
use md5;
use sha2::{Digest as ShaDigest, Sha256};

use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use copypasta::{ClipboardContext, ClipboardProvider};
use hex;
use rand::{thread_rng, RngCore};
use rfd::FileDialog;
use std::fs;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Debug, PartialEq)]
enum Method {
    MD5,
    SHA256,
    AESEncrypt,
    AESDecrypt,
}

pub struct MyApp {
    input_text: String,
    output_text: String,
    method: Method,
    key: String,
    iv: String,
    fixed_input_field: bool,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            input_text: String::new(),
            output_text: String::new(),
            method: Method::MD5,
            key: String::new(),
            iv: String::new(),
            fixed_input_field: true,
        }
    }
}

impl MyApp {
    fn aes_encrypt(&self, plaintext: &str, key: &[u8], iv: &[u8]) -> Result<String, String> {
        let cipher =
            Aes256Cbc::new_from_slices(key, iv).map_err(|e| format!("Init cipher error: {}", e))?;
        let ciphertext = cipher.encrypt_vec(plaintext.as_bytes());
        Ok(hex::encode(ciphertext))
    }

    fn aes_decrypt(&self, ciphertext_hex: &str, key: &[u8], iv: &[u8]) -> Result<String, String> {
        let cipher =
            Aes256Cbc::new_from_slices(key, iv).map_err(|e| format!("Init cipher error: {}", e))?;
        let ciphertext =
            hex::decode(ciphertext_hex).map_err(|e| format!("Hex decode error: {}", e))?;
        let decrypted_data = cipher
            .decrypt_vec(&ciphertext)
            .map_err(|e| format!("Decrypt error: {}", e))?;
        String::from_utf8(decrypted_data).map_err(|e| format!("UTF-8 error: {}", e))
    }

    fn generate_random_bytes_hex(len: usize) -> String {
        let mut buf = vec![0u8; len];
        thread_rng().fill_bytes(&mut buf);
        hex::encode(buf)
    }

    fn copy_to_clipboard(text: &str) {
        if let Ok(mut ctx) = ClipboardContext::new() {
            let _ = ctx.set_contents(text.to_string());
        }
    }
}

impl App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Import .txt").clicked() {
                        if let Some(path) = FileDialog::new()
                            .add_filter("Text Files", &["txt"])
                            .pick_file()
                        {
                            if let Ok(content) = fs::read_to_string(path) {
                                self.input_text = content;
                            }
                        }
                        ui.close_menu();
                    }
                    if ui.button("Export Output").clicked() {
                        if let Some(path) =
                            FileDialog::new().set_file_name("output.txt").save_file()
                        {
                            let _ = fs::write(path, &self.output_text);
                        }
                        ui.close_menu();
                    }
                });

                ui.menu_button("View", |ui| {
                    ui.checkbox(&mut self.fixed_input_field, "Fixed Text Field");
                });

                ui.menu_button("Help", |ui| {
                    ui.label("Made with 🦀 Rust + egui");
                    ui.label("v1.2.0 Encryptor GUI");
                    ui.label("github.com/solid-drink/encryptor_gui");
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.heading("🔐 Text Encryptor/Hasher");
                    });

                    ui.separator();
                    ui.label("Input teks:");

                    if self.fixed_input_field {
                        egui::ScrollArea::vertical()
                            .max_height(150.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.input_text)
                                        .desired_width(f32::INFINITY)
                                        .frame(true),
                                );
                            });
                    } else {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.input_text)
                                .desired_width(f32::INFINITY),
                        );
                    }

                    ui.add_space(10.0);

                    egui::ComboBox::from_label("Metode")
                        .selected_text(format!("{:?}", self.method))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.method, Method::MD5, "MD5");
                            ui.selectable_value(&mut self.method, Method::SHA256, "SHA256");
                            ui.selectable_value(
                                &mut self.method,
                                Method::AESEncrypt,
                                "AES Encrypt",
                            );
                            ui.selectable_value(
                                &mut self.method,
                                Method::AESDecrypt,
                                "AES Decrypt",
                            );
                        });

                    if matches!(self.method, Method::AESEncrypt | Method::AESDecrypt) {
                        ui.horizontal(|ui| {
                            ui.label("🔑 Key (32-byte hex):");
                            if ui.button("Copy").clicked() {
                                Self::copy_to_clipboard(&self.key);
                            }
                            if ui.button("Generate").clicked() {
                                self.key = Self::generate_random_bytes_hex(32);
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.key)
                                    .desired_width(f32::INFINITY),
                            );
                        });

                        ui.horizontal(|ui| {
                            ui.label("🧬 IV (16-byte hex):");
                            if ui.button("Copy").clicked() {
                                Self::copy_to_clipboard(&self.iv);
                            }
                            if ui.button("Generate").clicked() {
                                self.iv = Self::generate_random_bytes_hex(16);
                            }
                        });

                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.iv)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                    }

                    ui.add_space(10.0);

                    if ui.button("🔁 Proses").clicked() {
                        match self.method {
                            Method::MD5 => {
                                let digest = md5::compute(self.input_text.as_bytes());
                                self.output_text = format!("{:x}", digest);
                            }
                            Method::SHA256 => {
                                let mut hasher = Sha256::new();
                                hasher.update(self.input_text.as_bytes());
                                let result = hasher.finalize();
                                self.output_text = format!("{:x}", result);
                            }
                            Method::AESEncrypt => {
                                if self.key.is_empty() {
                                    self.key = Self::generate_random_bytes_hex(32);
                                }
                                if self.iv.is_empty() {
                                    self.iv = Self::generate_random_bytes_hex(16);
                                }

                                if let (Ok(key_bytes), Ok(iv_bytes)) =
                                    (hex::decode(&self.key), hex::decode(&self.iv))
                                {
                                    if key_bytes.len() != 32 || iv_bytes.len() != 16 {
                                        self.output_text =
                                            "❌ Key harus 32 byte & IV 16 byte (hex)!".into();
                                    } else {
                                        match self.aes_encrypt(
                                            &self.input_text,
                                            &key_bytes,
                                            &iv_bytes,
                                        ) {
                                            Ok(encrypted) => self.output_text = encrypted,
                                            Err(e) => self.output_text = format!("❌ Error: {}", e),
                                        }
                                    }
                                } else {
                                    self.output_text = "❌ Format key atau IV salah!".into();
                                }
                            }
                            Method::AESDecrypt => {
                                if let (Ok(key_bytes), Ok(iv_bytes)) =
                                    (hex::decode(&self.key), hex::decode(&self.iv))
                                {
                                    if key_bytes.len() != 32 || iv_bytes.len() != 16 {
                                        self.output_text =
                                            "❌ Key harus 32 byte & IV 16 byte (hex)!".into();
                                    } else {
                                        match self.aes_decrypt(
                                            &self.input_text,
                                            &key_bytes,
                                            &iv_bytes,
                                        ) {
                                            Ok(decrypted) => self.output_text = decrypted,
                                            Err(e) => self.output_text = format!("❌ Error: {}", e),
                                        }
                                    }
                                } else {
                                    self.output_text = "❌ Format key atau IV salah!".into();
                                }
                            }
                        }
                    }

                    ui.separator();
                    ui.label("Output:");
                    ui.add_sized(
                        [ui.available_width(), 150.0],
                        egui::TextEdit::multiline(&mut self.output_text)
                            .desired_rows(6)
                            .desired_width(f32::INFINITY),
                    );

                    if ui.button("📋 Copy Output").clicked() {
                        Self::copy_to_clipboard(&self.output_text);
                    }
                });
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Encryptor GUI",
        options,
        Box::new(|_cc| Box::new(MyApp::default())),
    )
}
