import cv2
from ultralytics import YOLO
import requests
import json

def run_inventory_scan(image_path):
    # 1. Load your custom weights
    model = YOLO('ai_model/best.pt')

    # 2. Run Inference
    results = model.predict(source=image_path, conf=0.25)

    for result in results:
        detections = []
        for box in result.boxes:
            det = {
                "class": result.names[int(box.cls[0])],
                "confidence": round(float(box.conf[0]), 2),
                "bbox": [round(float(x), 1) for x in box.xyxy[0].tolist()]
            }
            detections.append(det)

        # 3. Create the Payload
        # Note: We calculate top_confidence here for the PHP dashboard badge
        top_conf = max([d['confidence'] for d in detections]) if detections else 0
        
        payload = {
            "total_items": len(detections),
            "top_confidence": top_conf,
            "items": detections
        }

        # 4. Push to the PHP Bridge using Multipart
        url = "http://localhost/smart_inventory/api/upload_scan.php"
        
        try:
            # We open the image file in binary mode
            with open(image_path, 'rb') as img_file:
                # 'files' sends the binary, 'data' sends the JSON as a string
                files = {'image': img_file}
                data = {'json_data': json.dumps(payload)}
                
                # Removing custom headers; requests sets 'multipart/form-data' automatically
                response = requests.post(url, files=files, data=data)
                print(f"Server Response: {response.text}")
        except Exception as e:
            print(f"Connection Failed: {e}")

if __name__ == "__main__":
    # Ensure this path is correct for your local setup
    run_inventory_scan('ai_model/image.png')