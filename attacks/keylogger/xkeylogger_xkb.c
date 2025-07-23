#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <X11/keysym.h>
#include <unistd.h>

#define KEYMAP_SIZE 32

void fetch_keys_poll(Display *display) {
    char keymap[KEYMAP_SIZE];
    static char prev_keymap[KEYMAP_SIZE] = {0};
    
    XQueryKeymap(display, keymap);

    // Compare current keymap to the previous keymap to detect released keys
    printf("Keys released: ");
    for (int byte = 0; byte < KEYMAP_SIZE; byte++) {
        if (keymap[byte] != prev_keymap[byte]) {
            for (int bit = 0; bit < 8; bit++) {
                if ((prev_keymap[byte] & (1 << bit)) && !(keymap[byte] & (1 << bit))) {
                    int keycode = byte * 8 + bit;
                    printf("%d ", keycode);
                }
            }
        }
    }
    printf("\n");

    for (int i = 0; i < KEYMAP_SIZE; i++) {
        prev_keymap[i] = keymap[i];
    }
}

int main() {
    Display *display = XOpenDisplay(NULL);
    if (!display) {
        fprintf(stderr, "Unable to open X display.\n");
        return EXIT_FAILURE;
    }

    while (1) {
        fetch_keys_poll(display);
        usleep(10000); // Poll every 10ms
    }

    XCloseDisplay(display);
    return EXIT_SUCCESS;
}
