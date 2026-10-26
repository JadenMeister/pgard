<!-- corpus: expect=PG-XSS-003 -->
<template>
  <div class="post-body" v-html="post.html"></div>
</template>
<script>
export default {
  props: { post: { type: Object, required: true } },
};
</script>
