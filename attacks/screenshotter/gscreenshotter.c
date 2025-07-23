#include "gdk-pixbuf/gdk-pixbuf.h"
#include "gdk/gdk.h"
#include "glib.h"
#include <gtk/gtk.h>

static GdkPixbuf *capture_rectangle_screenshot(gint x, gint y, gint w, gint h) {
    GdkWindow *root;
    int root_width, root_height;
    GdkPixbuf *screenshot;

    root = gdk_get_default_root_window();
    root_width = gdk_window_get_width(root);
    root_height = gdk_window_get_height(root);

    /* Avoid rectangle parts outside the screen */
    if (x < 0)
        w += x;
    if (y < 0)
        h += y;

    x = MAX(0, x);
    y = MAX(0, y);

    if (x + w > root_width)
        w = root_width - x;
    if (y + h > root_height)
        h = root_height - y;

    screenshot = gdk_pixbuf_get_from_window(root, x, y, w, h);

    return screenshot;
}

int main(int argc, char **argv) {
    gdk_init(&argc, &argv);
    printf("Switch to gtk app\n");
    g_usleep(2000000);
    printf("Executing now...\n");
    GdkPixbuf *screenshot = capture_rectangle_screenshot(0, 0, 100, 100);
    GError* error = NULL;
    gdk_pixbuf_save(screenshot, "gscreenshot_test", "png", &error, NULL);
    printf("%p", screenshot);
    return 0;
}
