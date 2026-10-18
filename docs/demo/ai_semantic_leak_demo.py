"""
Slug Security - Level 4 AI Deep Semantic Guard Test File.
Tệp tin mẫu kiểm thử tính năng AI Model Deep Semantic Guard (Mức lọc Level 4).

MỤC ĐÍCH KIỂM THỬ -
  Chứng minh khả năng vượt trội của mô hình AI (Level 4 LLM) so với bộ lọc Regex truyền thống (Level 2).
  
KẾT QUẢ KHI QUÉT -
  - Khi quét ở Level 2 (Policy & Smart Regex Guard):
    ✅ KHÔNG BỊ PHÁT HIỆN (0 Cảnh báo / Pass).
    Lý do - Tên biến sử dụng ngữ cảnh vô hại ('security_stamp', 'node_prefix'), 
    không chứa từ khóa nhạy cảm (không có 'api_key', 'token', 'secret', 'password').
    Độ hỗn loạn chuỗi (Shannon Entropy) ở mức thấp (< 3.8).
    
  - Khi quét ở Level 4 (AI Model Deep Semantic Guard):
    ❌ BỊ PHÁT HIỆN NGAY LẬP TỨC (Flagged & Quarantined).
    Lý do - LLM hiểu ngữ nghĩa đoạn mã đang ghép nối thông tin để tạo chứng chỉ
    đặc quyền quản trị hệ thống (Master Admin Credential) mà không được bảo vệ.
"""

import urllib.request
import json


class CloudInfrastructureClient:
    """
    Client kết nối dịch vụ hạ tầng nội bộ của doanh nghiệp.
    """
    def __init__(self, region: str = "ap-southeast-1"):
        self.region = region
        self.service_url = "https://internal-cluster.enterprise.corp/api/v2"

    def obtain_master_admin_session(self):
        # Lập trình viên vô tình nhúng cứng chứng chỉ quản trị viên cấp cao:
        # Tên biến vô hại nhằm tránh các công cụ Regex tĩnh thông thường
        node_prefix = "prod"
        role_identifier = "superuser"
        security_stamp = "MasterRootCredential2026"
        
        # Lắp ghép chuỗi xác thực bypass quản trị viên
        master_credential_payload = f"{node_prefix}:{role_identifier}:{security_stamp}"
        
        req = urllib.request.Request(
            f"{self.service_url}/admin/escalate",
            data=json.dumps({"grant": master_credential_payload}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        return req


if __name__ == "__main__":
    client = CloudInfrastructureClient()
    print("Client initialized for region:", client.region)
