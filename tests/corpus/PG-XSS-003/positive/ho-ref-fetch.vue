<!-- corpus: expect=PG-XSS-003 -->
<template>
  <article v-html="body"></article>
</template>
<script setup>
import { ref, onMounted } from "vue";
const body = ref("");
onMounted(async () => {
  body.value = await (await fetch("/api/page")).text();
});
</script>
