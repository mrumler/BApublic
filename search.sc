@main def exec(cpgFile: String, outFile: String, prefix: String) = {
  importCpg(cpgFile)

  val sb = new StringBuilder();

  val skbuffmethods = cpg.method.parameter.typeFullNameExact("sk_buff*").method

  skbuffmethods.foreach { m =>
    {
      sb.append(prefix)
      sb.append("; ")
      sb.append(m.name)
      sb.append("; ")
      sb.append(m.lineNumber.mkString(", "))
      sb.append("; ")
      m.parameter.foreach { p =>
        {
          if (p.typeFullName.contains("sk_buff")) {
            sb.append(p.name)
            sb.append("; ")
          }
        }
      }
      sb.append('\n')
    }
  }

  sb.result() #>> outFile
}
