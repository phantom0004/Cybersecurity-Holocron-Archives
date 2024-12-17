import sounddevice as sd
import numpy as np
import wave

# UPDATE TO SUPPORT COMPRESSION
def record_audio(filename, duration, samplerate=44100, channels=1):
    print("Recording target audio ...")
    try:
        recording = sd.rec(int(duration * samplerate), samplerate=samplerate, channels=channels)
        sd.wait()  # Wait until recording is finished
    except Exception as err:
        return f"[-] Unable to capture user recording -> {err}"
        
    print("Recording finished")

    # Ensure the recorded data is in the correct format for saving as a WAV file
    try:
        recording = np.int16(recording * 32767)
    except Exception as err:
        return f"[-] Unable to store recording as a WAV file -> {err}"

    try:
        with wave.open(filename, 'w') as wf:
            wf.setnchannels(channels)
            wf.setsampwidth(2)  # 2 bytes for 'int16'
            wf.setframerate(samplerate)
            wf.writeframes(recording.tobytes())
    except Exception as err:
        return f"[-] Unable to write to WAV file -> {err}"
    
    return "success"

filename = "output_mic.wav"
duration = 5  # seconds
output_function = record_audio(filename, duration)

if output_function != "success":
    print(f"An error has occured -> {output_function}")
else:
    print(f"\nAudio recorded and saved as {filename}, located in same directory as this file")

# Need to implement the sending and compression of data