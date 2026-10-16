# Slug — Bộ Tài liệu Kỹ thuật & Hồ sơ Dự thi SICT Innovation Challenge 2026

Bộ tài liệu kỹ thuật hoàn chỉnh của dự án **Slug** được chuẩn hóa theo các tiêu chuẩn kỹ thuật nghiêm ngặt và barem chấm điểm của cuộc thi **SICT Innovation Challenge 2026 (Track: Tech Your Solutions — Đại học Công nghiệp Hà Nội)**:

1. **[SICT_INNOVATION_CHALLENGE_PROPOSAL.md](SICT_INNOVATION_CHALLENGE_PROPOSAL.md)**: **Báo cáo Giải pháp Dự thi Chính thức** — Trình bày toàn diện 7 mục: Đặt vấn đề thực tế, Tính khả thi, Tính sáng tạo, Ứng dụng AI, Phản biện kỹ thuật khoa học, Kịch bản thực nghiệm & Demo 3 phút, Cam kết mã nguồn mở.
2. **[01-PROBLEM.md](01-PROBLEM.md)**: **Đặt Vấn đề & Nhu cầu Thực tế** — Phân tích chi tiết bài toán bảo vệ mã nguồn của sinh viên và kỹ sư phần mềm khi làm việc với AI Coding Agent và chia sẻ qua mạng nội bộ.
3. **[02-SOLUTION.md](02-SOLUTION.md)**: **Giải pháp & Quy trình 3 Bước** — Quy trình tối giản: 1. Kiểm tra mã nguồn (`slug audit`) $\rightarrow$ 2. Cất bí mật và chạy test trong RAM (`slug env`) $\rightarrow$ 3. Chia sẻ P2P có kiểm soát (`slug add` & `slug get`).
4. **[03-AI-USAGE.md](03-AI-USAGE.md)**: **Ứng dụng Trí tuệ Nhân tạo (AI)** — Trợ lý AI phân tích ngữ cảnh, giải thích rủi ro bằng tiếng Việt, Stateful Cache BLAKE3 tiết kiệm chi phí, và chỉ thị dạy AI Agent (`.slug/ai-rule.md`).
5. **[04-ARCHITECTURE.md](04-ARCHITECTURE.md)**: **Kiến trúc Hệ thống & Ranh giới Bảo mật** — C++20 single-binary, cơ chế nạp biến môi trường vào RAM tiến trình con, VFS Jail closed-loop gating, 3 filter modes, và bắt tay P2P hậu lượng tử (NIST FIPS 203 ML-KEM-768) kèm TOTP 8 số tự hủy.
6. **[TUTORIAL_VI.md](TUTORIAL_VI.md)**: **Hướng dẫn Sử dụng Thực tế từ A-Z** — Cẩm nang dòng lệnh, kịch bản thực chiến và các câu lệnh hữu ích hàng ngày.

- **Mã nguồn mở chính thức:** [https://github.com/dotlinux26/slug](https://github.com/dotlinux26/slug)
- **Giấy phép:** Apache License 2.0
