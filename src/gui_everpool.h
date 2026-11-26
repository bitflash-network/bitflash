// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The Everpool window: the pools recorded on the chain (docs/pool-registry.md),
// which one this node mines, and creating one, without the command line.

#ifndef BITFLASH_GUI_EVERPOOL_H
#define BITFLASH_GUI_EVERPOOL_H

extern bool g_showEverpool;

// Called once per frame from the GUI loop; returns at once while closed.
// Nothing of it runs, and no thread starts, until the window is opened.
void DrawEverpoolWindow();

// gui.cpp: relaunch Bitflash with the same command line (the wallet storage
// wizard's "Restart Now"). False when the relaunch could not be started.
bool GuiRestartApplication();

#endif
