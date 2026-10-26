// corpus: expect=PG-XSS-002
import { useEffect, useState } from "react";

export function Bio({ id }: { id: string }) {
  const [bio, setBio] = useState("");
  useEffect(() => {
    fetch("/api/bio/" + id).then((r) => r.text()).then(setBio);
  }, [id]);
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
