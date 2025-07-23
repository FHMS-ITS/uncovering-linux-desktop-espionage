#include <QCoreApplication>
#include <QAudioDeviceInfo>
#include <QAudioFormat>
#include <QAudioInput>
#include <QFile>
#include <QDebug>

class AudioCapture : public QObject {
    Q_OBJECT

public:
    AudioCapture(QObject *parent = nullptr) : QObject(parent) {
        // Get the default input audio device
        QAudioDeviceInfo inputDevice = QAudioDeviceInfo::defaultInputDevice();
        qDebug() << "Using audio device:" << inputDevice.deviceName();

        // Set audio format
        QAudioFormat format;
        format.setSampleRate(44100);
        format.setChannelCount(1);
        format.setSampleSize(16);
        format.setCodec("audio/pcm");
        format.setByteOrder(QAudioFormat::LittleEndian);
        format.setSampleType(QAudioFormat::SignedInt);

        if (!inputDevice.isFormatSupported(format)) {
            qWarning() << "Default format not supported, trying to use the nearest.";
            format = inputDevice.nearestFormat(format);
        }

        // Create an audio input object
        audioInput = new QAudioInput(inputDevice, format, this);

        // Open a file to save the audio
        audioFile.setFileName("output.wav");
        audioFile.open(QIODevice::WriteOnly | QIODevice::Truncate);
        // audioFile.write(format.bytesForDuration(100000), 100000); // Pre-allocate space for 100ms of audio

        // Start capturing audio
        audioInput->start(&audioFile);
        qDebug() << "Recording audio...";
    }

private:
    QAudioInput *audioInput;
    QFile audioFile;
};

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv);

    AudioCapture audioCapture;

    return a.exec();
}
#include "mic_qt.moc"
