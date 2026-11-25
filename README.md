# Context-Aware IaC Security Gate

Repository này chuẩn bị tích hợp CI/CD cho prototype ưu tiên xử lý phát hiện bảo mật trong Terraform. Dự án nghiên cứu dùng ngữ cảnh kỹ thuật và ngữ cảnh nghiệp vụ để sắp xếp các finding mà scanner đã phát hiện.

## Prototype tham chiếu

Luồng xử lý theo D-039:

1. Tạo bản sao Terraform riêng để chạy validation, rồi quét cấu hình với Checkov.
2. Chuẩn hóa finding và trích xuất contextual features theo phạm vi đã duyệt. Giữ các finding ngoài phạm vi chấm điểm trong báo cáo.
3. Dùng Random Forest deployment model D-038 để tính điểm ưu tiên cho finding có đủ dữ liệu đầu vào. Score phục vụ xếp hạng trong lượt quét. Đánh giá khoa học được quản lý riêng trong repository nghiên cứu.
4. Ghi kết quả Gate cùng báo cáo và checksum.

| Trạng thái Gate | Ý nghĩa trong prototype D-039 |
| --- | --- |
| `PASS` (exit 0) | Xử lý hoàn tất và lượt quét có 0 failed finding. |
| `REVIEW` (exit 10) | Xử lý hoàn tất và có ít nhất một failed finding, kể cả finding chưa được chấm điểm. |
| `ERROR` (exit 20) | Việc xử lý chưa hoàn tất hoặc kết quả không đủ tin cậy. |

Gate decision dựa trên tình trạng hoàn tất và failed findings. Điểm Random Forest quyết định thứ tự ưu tiên trong danh sách được chấm.

## Báo cáo và lịch sử thực thi

Security Gate chạy ở chế độ `ADVISORY_ONLY`. Ba fixture CI-3B3 đã được chạy trên GitHub. CI-4 bổ sung báo cáo HTML và JSON cho những lượt chạy dùng workflow mới. [Workflow](.github/workflows/security-gate.yml)

1. Trong **Actions → Security Gate advisory**, chọn run và attempt cần xem. Job Summary ghi trạng thái Gate, trạng thái wrapper trước upload, số finding và tối đa năm finding đứng đầu.
2. Tải artifact `security-gate-<UTC_TIMESTAMP>_run-<RUN_ID>_attempt-<ATTEMPT>`. Giải nén vào thư mục riêng cho từng attempt. Trong thư mục đó chạy:

   ```bash
   sha256sum --check --strict checksums.sha256
   ```

3. Khi mọi file đều báo `OK`, mở `report.html` trong trình duyệt. HTML chạy offline. `report.md` chứa nội dung Job Summary. Mở `execution.json` để xem exit codes, run, context, provenance và checksum. Khi Gate JSON nguồn được xác minh và xuất thành công, `gate-result.json` giữ score, expected rank, tie size và đặc trưng của từng finding đã chấm. [Schema JSON v1](.github/reporting/gate-result-v1.schema.json)

`execution.json.gate_json_sha256` nhận diện bytes của Gate JSON nguồn trên runner. `gate_result_sha256` và sidecar của `gate-result.json` nhận diện bytes đã lọc. Checksum cho phép phát hiện bản tải bị thay đổi. Điểm D-038 phục vụ xếp hạng trong lượt chạy. Finding ngoài phạm vi hoặc thiếu đặc trưng vẫn xuất hiện với score và rank bằng `null`. Bản công bố lược bỏ tên tài nguyên do PR cung cấp, dữ liệu Terraform, log thô và đường dẫn tùy ý. `workflow_ref` chỉ nhánh của workflow điều khiển; `scanned_commit_sha` xác định đầu vào khi scan hoàn tất.

Workflow yêu cầu lưu artifact **30 ngày**, tùy giới hạn của repository. Mỗi attempt có artifact riêng. Nếu upload thất bại, bước cuối trả `ERROR/20`; trạng thái Gate đã xác minh vẫn có thể xem trong Job Summary. Lỗi bootstrap cho báo cáo chẩn đoán khi runner còn hoạt động. Run bị hủy hoặc runner chưa khởi tạo có thể thiếu artifact. Ba artifact CI-3B3 cũ chỉ lưu metadata và số đếm.

Để kiểm CI-4 trên GitHub sau khi đưa workflow lên `main`, chọn **Run workflow** cho từng fixture `pass`, `review`, `error`. Đối chiếu Gate và wrapper lần lượt với `PASS/0`, `REVIEW/10`, `ERROR/20`, cùng `Fixture expectation: PASS` và kết quả upload. Fixture REVIEW có một finding đã chấm và một finding ngoài phạm vi. Fixture ERROR cần đối chiếu trạng thái `terraform_validate` trong export. Luồng Terraform PR có lượt nghiệm thu riêng.

## Demo Pull Request CI-5

Fixture [CI-5](.github/ci_gate_fixtures/ci5/main.tf) là Terraform tổng hợp dùng để trình diễn kiểm tra tĩnh. Fixture sạch dùng lại [PASS](.github/ci_gate_fixtures/pass/main.tf).

Khi PR trong cùng repository nhắm vào `main` và thay đổi `terraform/**`, workflow **Security Gate PR signal** báo sự kiện cho workflow **Security Gate advisory** chạy từ nhánh mặc định. PR tự động đọc [cấu hình workload](config/business-context.json) từ commit điều khiển trên `main`. Cấu hình ban đầu là `dev / low / low` (CTX01). Mở artifact theo hướng dẫn trên và đối chiếu `execution.json.pr_number`, `input_commit_sha` và `scanned_commit_sha` với PR head. Khi push bản sửa vào cùng nhánh PR, kiểm tra run mới và lưu artifact lần trước vào thư mục riêng trước khi so sánh. GitHub yêu cầu payload `workflow_run` chỉ ra đúng một PR cùng repository để bước xác minh có thể tiếp tục.

Để so sánh hai bối cảnh với cùng đầu vào, vào **Actions → Security Gate advisory → Run workflow** trên `main`, chọn fixture `ci5` và lần lượt chọn `CTX01` (`dev / low / low`) và `CTX08` (`prod / high / high`). So sánh hai artifact có cùng `terraform_artifact_sha256`, model SHA-256, runtime commit và finding IDs. `context_profile_id` ghi profile đã chọn. Các score và rank trong `gate-result.json` dùng để trình diễn suy luận vận hành. Mức thay đổi score có thể khác nhau giữa các finding. Luồng PR giữ chế độ `ADVISORY_ONLY`.

## Dashboard và phản hồi PR (CI-4E)

Publisher nhận sự kiện hoàn tất của **Security Gate advisory**, bao gồm REVIEW và ERROR. Repository học thuật công khai cho phép xuất bản báo cáo đã lọc của các lượt đủ provenance trên cùng repository. Với PR tự động, publisher kiểm signal, repository, PR và commit. Với PR giả định, publisher kiểm pin SHA từ Gate tin cậy trên `main`. Publisher tính lại Terraform artifact SHA-256 từ các blob tại đúng commit và đối chiếu với báo cáo. Hệ thống áp dụng cùng kiểm tra byte cho fixture tin cậy. Record và HTML lịch sử được giữ theo run/attempt.

### Quy trình Developer

1. Tự tạo Terraform dưới thư mục `terraform/` ở nhánh của cùng repository. Đặt 1–64 file `.tf` hợp lệ trực tiếp trong thư mục này. Giới hạn mỗi file 1 MiB và tổng 2 MiB. Input scope hiện tại dùng loại file thường và tên ASCII chữ, số, dấu gạch, dấu chấm hoặc underscore. Nested directories, symlink, submodule, `.tf.json`, `.tfvars` và `.tfvars.json` nằm ngoài contract. Terraform dành cho repository công khai.
2. Qua Git, commit, push và mở PR vào `main`. Gate tự chạy cho thay đổi `terraform/**`. Quy trình chấp nhận Terraform mới khi đáp ứng input contract, kể cả cấu hình do công cụ sinh ra.
3. Đối chiếu SHA trong Job Summary hoặc bot comment, rồi mở báo cáo trên Pages. Lịch sử tìm được theo PR, run hoặc SHA. Khi không công bố được, xem thông báo **Publication skipped** hoặc lỗi trong workflow **Publish advisory security report** và lấy artifact CI-4 từ Gate run.
4. Báo cáo công khai chứa rule ID, finding digest, phân loại, các giá trị feature trong schema, điểm và hạng. Tên resource, tên/đường dẫn nguồn, span và tiêu đề từ scanner được lược khỏi projection mới. Terraform thô, credentials, raw Gate JSON và log thô nằm ngoài dữ liệu công bố. Bản công khai giữ checksum Gate export gốc để đối chiếu artifact CI-4. Giới hạn hồ sơ công khai là 64 findings; kết quả lớn hơn hoặc thiếu bằng chứng vẫn giữ Gate outcome và artifact nếu upload thành công.


### Bật Pages và kiểm thử

1. Trên GitHub chọn **Settings → Pages → Build and deployment → Source → GitHub Actions**. Trong **Actions → Publish advisory security report → Run workflow**, chọn `main`, để trống `source_run`. Lượt này khởi tạo hoặc dựng lại toàn bộ site từ lịch sử đã lưu. Xem URL thật trong environment `github-pages`. URL mặc định dự kiến là [Security Dashboard](https://phanquan277github.github.io/context-aware-iac-security-gate-ci/).
2. Dispatch lần lượt các fixture `pass`, `review`, `error` trên phiên bản mới. Đối chiếu digest artifact, trạng thái Gate/wrapper, score/rank và đường dẫn `reports/<RUN_ID>/attempt-<ATTEMPT>/report.html`. Các lượt chẩn đoán và scan chưa hoàn tất được phân biệt trong dashboard.
3. Rerun một fixture. Kiểm tra cả hai URL theo attempt và hai bản ghi trong `history.json`. Workflow yêu cầu retention 30 ngày cho artifact CI-4. Các trang và bản ghi trên nhánh `gh-pages` tồn tại theo vòng đời riêng.
4. Mở PR demo CI-5 từ cùng repository. Đối chiếu SHA trong comment bot với head của PR. Push bản remediated lên cùng PR, chờ báo cáo mới và kiểm comment được cập nhật tại chỗ. Mỗi kết quả có run/attempt riêng. Khi Pages deploy lỗi, comment dẫn đến Actions run. Nếu chủ repo thiết lập custom domain, đối chiếu và cập nhật hằng `SITE` trong publisher trước khi sử dụng liên kết công khai.
5. Khi bỏ lỡ một lượt hoặc upload/deploy lỗi, dispatch publisher trên `main` với `source_run` và `source_attempt` chính xác khi artifact còn tải được. Để riêng `source_run` trống nếu chỉ cần deploy lại các báo cáo đã lưu. Không cần chạy lại Gate.

Nhánh `gh-pages` dành riêng cho nội dung sinh tự động. Mỗi lần chạy xác minh record, giữ báo cáo cũ, xây lại chỉ mục rồi push fast-forward. Nhóm concurrency chung tuần tự hóa lưu trữ, deploy và comment. GitHub cho phép tối đa 100 lượt chờ với `queue: max`. Lịch sử tăng theo số attempt; chủ repo có thể sao lưu và chủ động loại bỏ cả thư mục attempt được chọn, sau đó chạy rebuild. Dashboard mới dùng lại nguyên bytes của HTML lịch sử, kể cả khi renderer cho báo cáo mới thay đổi. Quyền ghi lên nhánh lịch sử và nhánh mặc định là một phần của ranh giới tin cậy.

Dashboard dùng tệp tĩnh và tải `history.json` qua HTTP. Bản mẫu cục bộ có thể xem bằng `python3 -m http.server 8765 --bind 127.0.0.1 --directory docs/ci4e_acceptance/preview`, sau đó mở `http://127.0.0.1:8765/`. Mẫu nội bộ dùng metadata CI-4 để kiểm giao diện; việc thêm lịch sử công khai bắt đầu từ các lượt Gate có provenance CI-4E.


## Business context và so sánh (CI-5C)

| Loại đánh giá | Nguồn business context | Cập nhật comment chính thức |
|---|---|---|
| PR tự động | `config/business-context.json` tại commit điều khiển trên `main` | Có, nếu input thuộc phạm vi công bố và PR head còn khớp |
| PR giả định | `workflow_dispatch` trên `main` với tuple và head SHA được chọn | Chỉ xuất artifact và báo cáo Dashboard nếu đủ điều kiện |
| Fixture | `context_profile`, mặc định CTX01. CTX08 dùng với fixture `ci5` | Chỉ xuất artifact và báo cáo Dashboard nếu đủ điều kiện |

D-039 dùng `dev/prod` cho `environment`, `low/high` cho `asset_criticality` và `data_sensitivity`. Chủ workload cập nhật đúng ba trường trên `main`. Các đánh giá tự động tiếp theo đọc revision mới. Muốn đánh giá lại PR đang mở, cần một sự kiện PR đủ điều kiện. Config sai hoặc thiếu sinh diagnostic `BUSINESS_CONTEXT` với wrapper ERROR/20. Trang công khai giữ các báo cáo đã được công bố.

Đánh giá giả định xác minh PR còn mở và thuộc cùng repository, nhắm `main`, cùng SHA với `expected_head_sha` trước khi checkout. Context được truyền trực tiếp tới Gate D-039 từ workflow tin cậy. Execution và Gate export có `context_provenance` phiên bản `ci5c-context-v1`, gồm loại đánh giá, nguồn context, revision điều khiển, hash config khi có và pin của PR giả định. Report ghi các giá trị context thật và profile tương ứng. Chính sách công bố cấp repository phía trên áp dụng cho cả ba loại. Lượt PR giả định đủ điều kiện xuất hiện trên dashboard và dùng được trong so sánh.

Mục **So sánh bối cảnh** yêu cầu cùng artifact Terraform và commit đã quét, cùng runtime/model và schema tương thích, hai scan chấm điểm hoàn tất và context khác nhau. Đối chiếu `finding_id` một-một và đặc trưng kỹ thuật. Finding ngoài phạm vi hiển thị riêng với điểm/hạng trống. Số điểm thay đổi dùng ngưỡng tuyệt đối `1e-12` trên số gốc. Hạng và tie lấy từ export. Điểm ưu tiên có thể tăng hoặc giảm khi bối cảnh thay đổi.

Dashboard kiểm lịch sử lúc mở trang, khi bấm **Làm mới lịch sử**, sau mỗi 60 giây khi tab hiển thị và khi trở lại tab. Timestamp kiểm thành công là giờ trình duyệt. Timestamp sinh lịch sử theo bản được phục vụ. Khi lỗi tải, giữ bản hợp lệ cuối. Các asset mới dùng tên chứa SHA-256, và các báo cáo đã công bố giữ URL/bytes.

### Nghiệm thu hosted trên PR #2

Sau khi đưa CI-5C lên `main`, chạy các lệnh sau từ gốc repo. Hai dispatch PR dùng chung một SHA. Nếu PR head đổi giữa hai lệnh, lượt sau phải từ chối và sinh báo cáo chẩn đoán.

```bash
gh workflow run publish-security-report.yml --ref main
head_sha="$(gh pr view 2 --json headRefOid --jq .headRefOid)"
test -n "$head_sha"
gh workflow run security-gate.yml --ref main -f mode=on_demand_pr \
  -f pr_number=2 -f expected_head_sha="$head_sha" \
  -f environment=dev -f asset_criticality=low -f data_sensitivity=low
gh workflow run security-gate.yml --ref main -f mode=on_demand_pr \
  -f pr_number=2 -f expected_head_sha="$head_sha" \
  -f environment=prod -f asset_criticality=high -f data_sensitivity=high
```

Kiểm hai report mới xuất hiện trên dashboard, mở so sánh, đối chiếu 7 failed, 4 scored, 3 unsupported, 4 score thay đổi và 0 rank thay đổi. So sánh comment chính thức trước/sau hai lần dispatch. Sau đó kiểm luồng tự động bằng sự kiện PR đủ điều kiện trong lúc thay đổi config trên `main`. Xác minh Job Summary, config SHA, model input và score của lượt mới, rồi đưa config về context dự định trước khi tiếp tục CI5-T04 trên PR #2. Giữ advisory mode trong suốt nghiệm thu.

## Nguồn và ghi công cho runtime `ci-gate-v1`

- **GenIaC-SecBench — Animesh Shaw.** Benchmark dùng để huấn luyện model vận hành D-038 dùng dữ liệu từ revision `a9f0b979176e9127aa60c8e8197d03d9fffdda58`. Dataset công bố phần dữ liệu do dự án GenIaC tạo theo CC BY 4.0. Phần human reference theo điều khoản của từng nguồn upstream. [Dataset](https://huggingface.co/datasets/AnimeshShaw/GenIaC-SecBench) · [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- **AWS.** Taxonomy IAM D-008 dùng tên AWS actions và tham chiếu tài liệu về wildcard. Các nhóm capability do dự án xác định. [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/) · [AWS IAM Action](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html)
- **Checkov.** Runtime gọi Checkov 3.3.17 để quét Terraform. Applicability matrix dùng mã check. Bảng severity dùng mã và tên check từ dữ liệu quét Checkov. Mức severity và lý do gán mức do dự án xác định theo D-022. Checkov 3.3.17 được phát hành theo Apache License 2.0. [Checkov 3.3.17](https://pypi.org/project/checkov/3.3.17/)

<details>
<summary>Bản sao giấy phép đi kèm Checkov 3.3.17</summary>

```text
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2019 Palo Alto Networks

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

</details>
