// corpus: expect=PG-XSS-002
import { useSearchParams } from "next/navigation";

export default function Search() {
  const params = useSearchParams();
  const q = params.get("q") ?? "";
  return <p dangerouslySetInnerHTML={{ __html: `Results for ${q}` }} />;
}
