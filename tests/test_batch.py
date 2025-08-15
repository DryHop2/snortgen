import json

from snortsmith_rulegen.batch import run_batch


def test_run_batch_json_writes_rules(tmp_path):
    # Prepare batch file
    batch = [
        {"proto":"tcp","src_ip":"any","src_port":"any","dst_ip":"$HOME_NET","dst_port":"80","msg":"A","content":"cmd.exe"}
    ]
    bpath = tmp_path / "batch.json"
    bpath.write_text(json.dumps(batch))

    out_dir = tmp_path / "rules"
    out_file = out_dir / "local.rules"

    # Run (verbose True just to print; dry_run False to write)
    run_batch(filepath=str(bpath), outfile=str(out_file), verbose=False, dry_run=False, config={})

    text = out_file.read_text()
    assert 'alert tcp any any -> $HOME_NET 80 (' in text
    assert 'msg:"A"' in text and 'content:"cmd.exe"' in text


def test_run_batch_csv_respects_outfile(tmp_path):
    csv_text = "msg,content,outfile\nA,cmd.exe," + str(tmp_path / "custom.rules") + "\n"
    bpath = tmp_path / "batch.csv"
    bpath.write_text(csv_text)

    run_batch(filepath=str(bpath), outfile=str(tmp_path / "fallback.rules"), verbose=False, dry_run=False, config={})

    assert (tmp_path / "custom.rules").exists()
    assert not (tmp_path / "fallback.rules").exists()