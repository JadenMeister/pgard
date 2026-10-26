<!-- corpus: expect=PG-XSS-003 -->
<template>
  <section>
    <article v-html="post.body"></article>
  </section>
</template>
<script>
export default {
  data() {
    return { post: { body: "" } };
  },
  async created() {
    const res = await fetch("/api/post/1");
    this.post = await res.json();
  },
};
</script>
