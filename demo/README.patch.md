<!-- demo/README.patch.md — staged README block per .omc/plans/kube-policies-demo-video.md §5.5.
     This file is NOT applied automatically. The README is patched in a separate,
     user-approved turn that swaps the PLACEHOLDER src below for the
     user-attachments URL produced by `gh release upload` (default per Architect A10)
     or by a drag-and-drop attachment URL. Until then this is just a staged
     preview committed alongside the demo pipeline. -->

## Demo

<!-- 60-second walkthrough of kube-policies. PLACEHOLDER — replace the src
     below with the user-attachments URL produced by either:
       (a) gh release upload v<X.Y.Z> demo/dist/kube-policies-demo.mp4
           and then paste the release-asset URL, OR
       (b) drag-and-drop the MP4 into a GitHub issue/PR draft to obtain
           a user-attachments.githubusercontent.com URL. -->
<video src="https://user-images.githubusercontent.com/UPLOAD-HASH/kube-policies-demo.mp4"
       controls muted playsinline></video>

*Real-time admission control, PolicyException-based exception management,
and the live decisions dashboard — recorded on a local Kind cluster.*

See [demo/AGENTS.md](demo/AGENTS.md) for regen instructions.
