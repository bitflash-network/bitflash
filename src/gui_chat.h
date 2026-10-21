// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The btfchat window. Kept out of gui.cpp because the chat is its own thing:
// its own identity, its own onion service, its own lock. Mixing its state into
// the wallet window's would be the first step towards mixing the identities.

#ifndef BITFLASH_GUI_CHAT_H
#define BITFLASH_GUI_CHAT_H

// Set by the menu item; the window closes itself when the session locks.
extern bool g_showChat;

// Draw the chat window. Called once per frame from the GUI loop, and returns
// immediately when the window is closed. Never blocks: everything that touches
// the network goes through a worker thread, because one Tor dial is seconds and
// a frame is sixteen milliseconds.
void DrawChatWindow();

// btfchat's own entry point: its own GLFW window, its own loop, and nothing on
// screen but the chat. This is what btfchat.exe runs instead of the wallet GUI.
//
// It is a separate PROCESS with a separate data directory, so the chat's wallet,
// chain, keys, Tor and onion service are not the miner's. It is not separate
// SOURCE: both binaries are built from the same modules on purpose, because two
// copies of a crypto module means a fix landing in one and being forgotten in
// the other, which is the easiest way to leave a hole open for months.
int RunChatGUI(int argc, char* argv[]);

#endif
