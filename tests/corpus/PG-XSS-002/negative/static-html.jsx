// corpus: expect=none
export function Legal() {
  return <div dangerouslySetInnerHTML={{ __html: "<b>All rights reserved</b>" }} />;
}
