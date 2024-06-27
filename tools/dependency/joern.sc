@main def exec() = {
    importCpg("./cpg.bin")
    cpg.all.toJsonPretty #> "./cpg_all.json"
    cpg.method.name.l #> "./cpg_all_method.log"
}