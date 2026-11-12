// The settings window on macOS: one NSWindow with a WKWebView that shows the
// page served by the local proxy.

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

@interface CGPanel : NSObject <NSApplicationDelegate, NSWindowDelegate, WKUIDelegate,
                               WKNavigationDelegate, WKScriptMessageHandler>
@property(strong) NSWindow *window;
@property(strong) WKWebView *web;
@property(strong) NSURL *home;
@property BOOL selftest;
@end

@implementation CGPanel

- (void)load {
	[self.web loadRequest:[NSURLRequest requestWithURL:self.home]];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)app {
	return YES;
}

// A second launch of the app lands here instead of opening another window.
- (BOOL)applicationShouldHandleReopen:(NSApplication *)app hasVisibleWindows:(BOOL)visible {
	[self.window makeKeyAndOrderFront:nil];
	return YES;
}

- (BOOL)applicationSupportsSecureRestorableState:(NSApplication *)app {
	return YES;
}

// The page tells which theme the user picked; the title bar follows it.
- (void)userContentController:(WKUserContentController *)c didReceiveScriptMessage:(WKScriptMessage *)m {
	if (![m.body isKindOfClass:[NSString class]]) {
		return;
	}
	if ([m.body isEqualToString:@"dark"]) {
		self.window.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
	} else if ([m.body isEqualToString:@"light"]) {
		self.window.appearance = [NSAppearance appearanceNamed:NSAppearanceNameAqua];
	} else {
		self.window.appearance = nil;
	}
}

// Without these, alert() and confirm() in the page do nothing in a WKWebView.
- (void)webView:(WKWebView *)w runJavaScriptAlertPanelWithMessage:(NSString *)message
		initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(void))done {
	NSAlert *a = [NSAlert new];
	a.messageText = message;
	[a addButtonWithTitle:@"OK"];
	[a beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) { done(); }];
}

- (void)webView:(WKWebView *)w runJavaScriptConfirmPanelWithMessage:(NSString *)message
		initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(BOOL))done {
	NSAlert *a = [NSAlert new];
	a.messageText = message;
	[a addButtonWithTitle:@"OK"];
	[a addButtonWithTitle:@"Отмена"];
	[a beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
		done(r == NSAlertFirstButtonReturn);
	}];
}

// Only the settings page lives in this window; any other link goes to the
// browser.
- (void)webView:(WKWebView *)w decidePolicyForNavigationAction:(WKNavigationAction *)action
		decisionHandler:(void (^)(WKNavigationActionPolicy))decide {
	NSURL *u = action.request.URL;
	BOOL web = [u.scheme isEqualToString:@"http"] || [u.scheme isEqualToString:@"https"];
	BOOL ours = [u.host isEqualToString:self.home.host] && [u.port isEqual:self.home.port];
	if (web && !ours) {
		[[NSWorkspace sharedWorkspace] openURL:u];
		decide(WKNavigationActionPolicyCancel);
		return;
	}
	decide(WKNavigationActionPolicyAllow);
}

- (WKWebView *)webView:(WKWebView *)w createWebViewWithConfiguration:(WKWebViewConfiguration *)c
		forNavigationAction:(WKNavigationAction *)action windowFeatures:(WKWindowFeatures *)f {
	if (action.request.URL) {
		[[NSWorkspace sharedWorkspace] openURL:action.request.URL];
	}
	return nil;
}

- (void)webView:(WKWebView *)w didFinishNavigation:(WKNavigation *)n {
	if (!self.selftest) {
		return;
	}
	// Give the page a moment to fetch its state with the key from the URL.
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		NSString *js = @"document.title + ' | panel ' + (document.getElementById('app').hidden ? 'hidden' : 'shown')"
		                " + ' | servers ' + document.querySelectorAll('#servers li').length";
		[w evaluateJavaScript:js completionHandler:^(id result, NSError *err) {
			printf("selftest: %s\n", [[NSString stringWithFormat:@"%@", err ? err : result] UTF8String]);
			exit(err ? 1 : 0);
		}];
	});
}

// The proxy may be restarting; try again shortly.
- (void)webView:(WKWebView *)w didFailProvisionalNavigation:(WKNavigation *)n withError:(NSError *)err {
	if (self.selftest) {
		printf("selftest: load failed: %s\n", err.localizedDescription.UTF8String);
		exit(1);
	}
	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC), dispatch_get_main_queue(), ^{
		[self load];
	});
}

@end

static NSMenuItem *item(NSMenu *menu, NSString *title, SEL action, NSString *key) {
	return [menu addItemWithTitle:title action:action keyEquivalent:key];
}

// The Edit menu is what makes Cmd+C, Cmd+V and friends work in text fields.
static void buildMenu(void) {
	NSMenu *bar = [NSMenu new];

	NSMenu *app = [NSMenu new];
	item(app, @"Скрыть Claudeguard", @selector(hide:), @"h");
	NSMenuItem *others = item(app, @"Скрыть остальные", @selector(hideOtherApplications:), @"h");
	others.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagOption;
	item(app, @"Показать все", @selector(unhideAllApplications:), @"");
	[app addItem:[NSMenuItem separatorItem]];
	item(app, @"Завершить Claudeguard", @selector(terminate:), @"q");
	[[bar addItemWithTitle:@"" action:nil keyEquivalent:@""] setSubmenu:app];

	NSMenu *edit = [[NSMenu alloc] initWithTitle:@"Правка"];
	item(edit, @"Отменить", @selector(undo:), @"z");
	item(edit, @"Повторить", @selector(redo:), @"Z");
	[edit addItem:[NSMenuItem separatorItem]];
	item(edit, @"Вырезать", @selector(cut:), @"x");
	item(edit, @"Скопировать", @selector(copy:), @"c");
	item(edit, @"Вставить", @selector(paste:), @"v");
	item(edit, @"Выбрать все", @selector(selectAll:), @"a");
	[[bar addItemWithTitle:@"" action:nil keyEquivalent:@""] setSubmenu:edit];

	NSMenu *win = [[NSMenu alloc] initWithTitle:@"Окно"];
	item(win, @"Свернуть", @selector(performMiniaturize:), @"m");
	item(win, @"Закрыть", @selector(performClose:), @"w");
	[[bar addItemWithTitle:@"" action:nil keyEquivalent:@""] setSubmenu:win];

	NSApp.mainMenu = bar;
	NSApp.windowsMenu = win;
}

// cgShowWindow runs the window until it is closed; it must be called on the
// main thread. With selftest the window stays hidden: the page is loaded,
// one line about it is printed and the process exits.
int cgShowWindow(const char *url, const void *icon, int iconLen, int selftest) {
	@autoreleasepool {
		[NSApplication sharedApplication];
		CGPanel *panel = [CGPanel new];
		panel.selftest = selftest;
		panel.home = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
		if (!panel.home) {
			return 1;
		}
		NSApp.delegate = panel;
		// The app is an agent (no Dock icon) while it only installs or sits in
		// the menu bar; with a window it becomes a regular app.
		[NSApp setActivationPolicy:selftest ? NSApplicationActivationPolicyProhibited
		                                    : NSApplicationActivationPolicyRegular];
		if (icon && iconLen > 0 && ![[NSBundle mainBundle] bundleIdentifier]) {
			NSImage *img = [[NSImage alloc] initWithData:[NSData dataWithBytes:icon length:iconLen]];
			if (img) {
				NSApp.applicationIconImage = img;
			}
		}
		buildMenu();

		NSWindow *window = [[NSWindow alloc]
			initWithContentRect:NSMakeRect(0, 0, 1040, 780)
			          styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
			                    NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
			            backing:NSBackingStoreBuffered
			              defer:NO];
		window.title = @"Claudeguard";
		window.releasedWhenClosed = NO;
		window.minSize = NSMakeSize(560, 480);
		window.delegate = panel;
		// The title bar takes the colour of the page under it.
		window.titlebarAppearsTransparent = YES;
		window.backgroundColor = [NSColor colorWithName:nil dynamicProvider:^NSColor *(NSAppearance *a) {
			BOOL dark = [[a bestMatchFromAppearancesWithNames:@[NSAppearanceNameAqua, NSAppearanceNameDarkAqua]]
				isEqualToString:NSAppearanceNameDarkAqua];
			return dark ? [NSColor colorWithSRGBRed:0x26 / 255.0 green:0x26 / 255.0 blue:0x24 / 255.0 alpha:1]
			            : [NSColor colorWithSRGBRed:0xFA / 255.0 green:0xF9 / 255.0 blue:0xF5 / 255.0 alpha:1];
		}];
		panel.window = window;

		WKWebViewConfiguration *conf = [WKWebViewConfiguration new];
		[conf.userContentController addScriptMessageHandler:panel name:@"claudeguard"];
		WKWebView *web = [[WKWebView alloc] initWithFrame:window.contentView.bounds configuration:conf];
		web.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
		web.UIDelegate = panel;
		web.navigationDelegate = panel;
		// No white flash before the page paints in the dark theme.
		[web setValue:@NO forKey:@"drawsBackground"];
		[window.contentView addSubview:web];
		panel.web = web;
		[panel load];

		if (selftest) {
			dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
				printf("selftest: timed out\n");
				exit(1);
			});
		} else {
			[window center];
			[window setFrameAutosaveName:@"ClaudeguardPanel"];
			[window makeKeyAndOrderFront:nil];
			[NSApp activateIgnoringOtherApps:YES];
		}
		[NSApp run];
	}
	return 0;
}

// cgActivate brings the app of another process to the front.
void cgActivate(int pid) {
	@autoreleasepool {
		NSRunningApplication *app = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
		[app activateWithOptions:NSApplicationActivateAllWindows];
	}
}

// cgTrash moves a file or a folder to the Trash.
int cgTrash(const char *path) {
	@autoreleasepool {
		NSURL *u = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
		return [[NSFileManager defaultManager] trashItemAtURL:u resultingItemURL:nil error:nil] ? 0 : 1;
	}
}
