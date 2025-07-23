#include <QApplication>
#include <QScreen>
#include <QPixmap>
#include <QImage>
#include <QFileDialog>
#include <QDir>
#include <QDebug>

bool saveScreenshot(const QString& filename) {
    // Get the primary screen
    QScreen* screen = QGuiApplication::primaryScreen();

    if (screen == nullptr) {
        qWarning() << "Primary screen not found.";
        return false;
    }

    // Grab the window (in this case, the entire screen)
    QPixmap pixmap = screen->grabWindow(0);

    // Save the pixmap to disk
    if (!pixmap.save(filename)) {
        qWarning() << "Failed to save screenshot to" << filename;
        return false;
    }

    return true;
}

int main(int argc, char** argv) {
    // Create a QApplication instance
    QApplication app(argc, argv);

    // Get the current date and time for the filename
    QString filename = QDir::homePath() + "/screenshot_qt5" + ".png";

    // Save the screenshot
    if (saveScreenshot(filename)) {
        qDebug() << "Screenshot saved to" << filename;
    } else {
        qWarning() << "Failed to save screenshot.";
    }

    return 0;
}
