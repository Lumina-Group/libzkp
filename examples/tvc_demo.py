import libzkp
import time
import os
import sys
from PIL import Image, ImageDraw
import matplotlib.pyplot as plt

def create_waveform_plot(frames, fps, filename="tvc_waveform.png"):
    """輝度変化の時系列グラフを作成"""
    plt.figure(figsize=(10, 4))
    plt.plot(frames, color='green', linewidth=1)
    plt.title(f"Temporal Visual Code Signal (FPS: {fps})")
    plt.xlabel("Frame")
    plt.ylabel("Brightness")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(filename)
    print(f"Waveform plot saved to {filename}")

def create_signal_gif(frames, fps, filename="tvc_signal.gif"):
    """輝度変化を視覚化したGIF動画を作成"""
    print(f"Generating GIF ({len(frames)} frames)...")
    
    images = []
    size = (200, 200)
    
    for val in frames:
        # 輝度値(0.0-1.0)をグレイスケール(0-255)に変換
        # 視認性を高めるため、0.2以下は0, 0.8以上は255のようにコントラストをつけてもいいが、
        # ここではリニアに変換しつつ、少し強調する
        brightness = int(max(0, min(255, val * 255)))
        
        # 画像生成 (L = Grayscale)
        img = Image.new('L', size, color=brightness)
        
        # 中央に「REC」のようなインジケータを入れる（オプション）
        draw = ImageDraw.Draw(img)
        # 枠線
        draw.rectangle([0, 0, size[0]-1, size[1]-1], outline=128, width=2)
        
        images.append(img)
    
    # GIF保存
    # durationはミリ秒単位。1000ms / fps
    duration = int(1000 / fps)
    
    images[0].save(
        filename,
        save_all=True,
        append_images=images[1:],
        duration=duration,
        loop=0
    )
    print(f"Signal video saved to {filename}")

def main():
    print("=== Temporal Visual Code (TVC) Demo with ZKP ===")
    
    # 1. Setup (Server/Screen)
    # 秘密値sと時刻t
    secret_s = 1234567890123456789
    time_t = int(time.time())
    fps = 30 # デモ用に少し遅くする
    
    print(f"[Sender] Generating signal for S={secret_s}, T={time_t} @ {fps}fps")
    
    # 2. Transmission (Camera Simulation)
    # 波形生成と復号シミュレーション
    try:
        frames, decoded_s, decoded_t = libzkp.tvc_simulate_transmission(secret_s, time_t, fps)
    except Exception as e:
        print(f"Error during transmission simulation: {e}")
        return

    print(f"[Receiver] Captured {len(frames)} frames")
    print(f"[Receiver] Decoded: S={decoded_s}, T={decoded_t}")
    
    # 3. Visualization (Generate Video/Image)
    create_waveform_plot(frames, fps, "tvc_waveform.png")
    create_signal_gif(frames, fps, "tvc_signal.gif")
    
    # 4. Proof Generation (Client Device)
    # 現在時刻とのズレを検証するためのパラメータ
    current_time = int(time.time())
    tolerance = 60 # 60秒以内の遅延は許容
    
    print(f"[Receiver] Generating ZK Proof...")
    print(f"           Current Time: {current_time}")
    print(f"           Tolerance: {tolerance}s")
    
    start_time = time.time()
    try:
        # 証明生成: "私は正当なコミットメント(S, T)を知っており、TはCurrent Timeに近い"
        proof_bytes, public_inputs = libzkp.tvc_prove_reception(decoded_s, decoded_t, current_time, tolerance)
        print(f"[Receiver] Proof generated in {time.time() - start_time:.4f}s")
        print(f"[Receiver] Proof size: {len(proof_bytes)} bytes")
    except Exception as e:
        print(f"Error during proof generation: {e}")
        import traceback
        traceback.print_exc()
        return

    # 5. Verification (Server)
    print(f"[Server] Verifying Proof...")
    try:
        is_valid = libzkp.tvc_verify_reception(proof_bytes, public_inputs)
        if is_valid:
            print(">>> VERIFICATION SUCCESS: User is authenticated.")
        else:
            print(">>> VERIFICATION FAILED: Invalid proof.")
    except Exception as e:
        print(f"Error during verification: {e}")

if __name__ == "__main__":
    main()
