// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The block explorer window, on top of explorer.h.

#ifndef BITFLASH_GUI_EXPLORER_H
#define BITFLASH_GUI_EXPLORER_H

extern bool g_showExplorer;

// Called once per frame from the GUI loop; returns at once while closed.
void DrawExplorerWindow();
// Opens the window on a transaction.
void ExplorerOpenTx(const uint256& txid);

#endif
